/* ssl.c - HTTPS support functions
**
** Copyright (C) 2017  Joachim Nilsson <troglobit@gmail.com>
** All rights reserved.
**
** Redistribution and use in source and binary forms, with or without
** modification, are permitted provided that the following conditions
** are met:
** 1. Redistributions of source code must retain the above copyright
**    notice, this list of conditions and the following disclaimer.
** 2. Redistributions in binary form must reproduce the above copyright
**    notice, this list of conditions and the following disclaimer in the
**    documentation and/or other materials provided with the distribution.
**
** THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
** ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
** IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
** ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
** FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
** DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
** OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
** HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
** LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
** OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
** SUCH DAMAGE.
*/

#include <config.h>
#include <sys/stat.h>
#include <unistd.h>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/x509_vfy.h>
#include <openssl/pem.h>
#include <openssl/crypto.h>
#include <openssl/engine.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#include "file.h"
#include "libhttpd.h"

void *httpd_ssl_init(char *cert, char *key)
{
	SSL_CTX *ctx;

	SSL_load_error_strings();
	OpenSSL_add_ssl_algorithms();

	ctx = SSL_CTX_new(SSLv23_server_method());
	if (!ctx)
		goto error;

	/* Enable bug workarounds. */
	SSL_CTX_set_options(ctx, SSL_OP_ALL);

	/* Disable insecure SSL/TLS versions. */
	SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2); /* DROWN */
	SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv3); /* POODLE */
	SSL_CTX_set_options(ctx, SSL_OP_NO_TLSv1); /* BEAST */

#if HAVE_DECL_SSL_CTX_SET_ECDH_AUTO
	SSL_CTX_set_ecdh_auto(ctx, 1);
#endif

 	SSL_CTX_set_default_verify_paths(ctx);
 	SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);

	if (SSL_CTX_use_certificate_file(ctx, cert, SSL_FILETYPE_PEM) < 0)
		goto error;

	if (SSL_CTX_use_PrivateKey_file(ctx, key, SSL_FILETYPE_PEM) < 0 )
		goto error;

	return ctx;
error:
	ERR_print_errors_fp(stderr);
	return NULL;
}

void httpd_ssl_exit(httpd_server *hs)
{
	if (hs->ctx) {
#if HAVE_DECL_SSL_COMP_FREE_COMPRESSION_METHODS
		SSL_COMP_free_compression_methods();
#endif
		SSL_CTX_free(hs->ctx);
		hs->ctx = NULL;

		ENGINE_cleanup();
		ERR_free_strings();
		ERR_remove_state(0);
		EVP_cleanup();
		CRYPTO_cleanup_all_ex_data();
		CONF_modules_free();
		CONF_modules_unload(1);
		COMP_zlib_cleanup();
	}
}

int httpd_ssl_open(httpd_conn *hc)
{
	SSL *ssl;
	SSL_CTX *ctx = NULL;

	if (!hc) {
		errno = EINVAL;
		return 1;
	}

	hc->ssl = NULL;
	if (hc->hs)
		ctx = hc->hs->ctx;

	if (ctx) {
		hc->ssl = SSL_new(ctx);
		if (!hc->ssl)
			return 1;

		SSL_set_fd(hc->ssl, hc->conn_fd);
		if (SSL_accept(hc->ssl) <= 0) {
			SSL_free(hc->ssl);
			return 1;
		}
	}

	return 0;
}

void httpd_ssl_close(httpd_conn *hc)
{
	if (hc->ssl) {
		SSL_free(hc->ssl);
		hc->ssl = NULL;
	}
	close(hc->conn_fd);
}

void httpd_ssl_shutdown(httpd_conn *hc)
{
	if (hc->ssl)
		SSL_shutdown(hc->ssl);
}

ssize_t httpd_ssl_read(httpd_conn *hc, void *buf, size_t len)
{
	if (hc->ssl)
		return SSL_read(hc->ssl, buf, len);

	/* Yes, it's a regular read() here, not file_read() */
	return read(hc->conn_fd, buf, len);
}

ssize_t httpd_ssl_write(httpd_conn *hc, void *buf, size_t len)
{
	if (hc->ssl)
		return SSL_write(hc->ssl, buf, len);

	return file_write(hc->conn_fd, buf, len);
}

ssize_t httpd_ssl_writev(httpd_conn *hc, struct iovec *iov, size_t num)
{
	if (hc->ssl) {
		char *buf;
		size_t i, pos = 0, len = 0;
		ssize_t rc;

		for (i = 0; i < num; i++)
			len += iov[i].iov_len;

		buf = malloc(len);
		for (i = 0; i < num; i++) {
			memcpy(&buf[pos], iov[i].iov_base, iov[i].iov_len);
			pos += iov[i].iov_len;
		}

		rc = SSL_write(hc->ssl, buf, len);
		if (rc < 0 && BIO_should_retry(SSL_get_wbio(hc->ssl))) {
			usleep(100000);
			rc = SSL_write(hc->ssl, buf, len);
		}

		free(buf);
		if (rc <= 0) {
			rc = SSL_get_error(hc->ssl, rc);
			switch (rc)
			{
			case SSL_ERROR_WANT_WRITE:
				errno = EAGAIN;
				break;

			case SSL_ERROR_SYSCALL:
				/* errno set already */
				break;

			default:
				errno = EINVAL;
				break;
			}

			/* Signal error to callee, like writev() */
			rc = -1;
		}

		return rc;
	}

	return writev(hc->conn_fd, iov, num);
}
