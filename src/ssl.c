/* ssl.c - HTTPS support functions
**
** Copyright (C) 2017-2018  Joachim Nilsson <troglobit@gmail.com>
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
** THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
** AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
** IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
** ARE DISCLAIMED.  IN NO EVENT SHALL THE COPYRIGHT OWNERS OR CONTRIBUTORS BE
** LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
** CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
** SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
** INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
** CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
** ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF
** THE POSSIBILITY OF SUCH DAMAGE.
*/

#include <config.h>
#include <fcntl.h>
#include <poll.h>
#include <string.h>
#include <syslog.h>
#include <sys/stat.h>
#include <sys/uio.h>
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

#include "libhttpd.h"
#include "file.h"
#include "ssl.h"

static int proto_to_version(char *proto)
{
	struct {
		char *proto;
		int   version;
	} supported[] = {
		{ "SSLv3",   SSL3_VERSION   }, /* 0x300 */
		{ "TLSv1",   TLS1_VERSION   }, /* 0x301 */
		{ "TLSv1.1", TLS1_1_VERSION }, /* 0x302 */
		{ "TLSv1.2", TLS1_2_VERSION }, /* 0x303 */
		{ "TLSv1.3", TLS1_3_VERSION }, /* 0x304 */
//		{ "TLSv1.4", TLS1_4_VERSION }, /* 0x305 */
		{ NULL, 0 }
	};
	int i, version;

	/* User is Kimi Räikkönen */
	if (!strncmp(proto, "0x3", 3)) {
		errno = 0;
		version = strtoul(proto, NULL, 0);
		if (errno)
			return -1;

		return version;
	}

	for (i = 0; supported[i].proto; i++) {
		if (!strcmp(proto, supported[i].proto))
			return supported[i].version;
	}

	return -1;
}

static void append(char *str, const char *c, size_t len)
{
	if (strlen(str) + strlen(c) + 1 >= len)
		return;

	if (str[0])
		strcat(str, ":");
	strcat(str, c);
}

static void split_ciphers(char *orig, char **list, char **suite)
{
	size_t len;
	char *str, *pre, *post, *c;

	len = strlen(orig) + 1;
	str = strdup(orig);
	pre = calloc(1, len);
	post = calloc(1, len);

	if (str && pre && post) {
		c = strtok(str, ":");
		while (c) {
			if (strchr(c, '_'))
				append(post, c, len);
			else
				append(pre, c, len);

			c = strtok(NULL, ":");
		}
	}

	if (str)
		free(str);

	*list = pre;
	*suite = post;
}

static void dump_supported_ciphers(SSL_CTX *ctx)
{
	STACK_OF(SSL_CIPHER) *ciphers;
	const SSL_CIPHER *cipher;
	size_t len;
	char *buf;
	int i, num;

	ciphers = SSL_CTX_get_ciphers(ctx);
	if (!ciphers) {
		syslog(LOG_WARNING, "No SSL ciphers set up!");
		return;
	}

	num = sk_SSL_CIPHER_num(ciphers);
	if (num <= 0) {
		buf = strdup("none");
		goto error;
	}

	buf = calloc(num, 50);
	if (!buf)
		return;

	len = num * 50;
	for (i = 0; i < num; i++) {
		cipher = sk_SSL_CIPHER_value(ciphers, i);
		append(buf, SSL_CIPHER_get_name(cipher), len);
	}
error:
	syslog(LOG_DEBUG, "SSL ciphers enabled: %s", buf);
	free(buf);
}

void *httpd_ssl_init(char *cert, char *key, char *dhparm, char *proto, char *ciphers)
{
	SSL_CTX *ctx;
	char *list, *suite;
	int min_version, rc = 0;

	ctx = SSL_CTX_new(SSLv23_method());
	if (!ctx)
		return NULL;

	/* Disable insecure SSL/TLS versions:
	 *
	 * - SSLv2 has the DROWN vulnerability
	 * - SSLv3 was POODLE
	 * - TLSv1 had BEAST
	 *
	 * ... and then we had CRIME, which forced us to disable
	 * compression.  All these required SSL_CTX_set_options(), but
	 * OpenSSL v1.1.0 recommends SSL_CTX_set_min_proto_version(),
	 * which is far easier to understand as an end-user.  Also,
	 * compression is disabled by default in OpenSSL v1.1.0, which
	 * is what the configure script now requires.
	 */
	min_version = proto_to_version(proto);
	if (-1 == min_version) {
		syslog(LOG_ERR, "Unknown SSL protocol '%s'", proto);
		goto error;
	}
	SSL_CTX_set_min_proto_version(ctx, min_version);

	if (ciphers) {
		split_ciphers(ciphers, &list, &suite);
		if (list) {
			rc += SSL_CTX_set_cipher_list(ctx, list);
			free(list);
		}
		if (suite) {
			rc += SSL_CTX_set_ciphersuites(ctx, suite);
			free(suite);
		}
		if (!rc) {
			syslog(LOG_ERR, "Invalid SSL ciphers '%s'", ciphers);
			goto error;
		}
	}
	dump_supported_ciphers(ctx);

	/* Best practices: prefer our ciphers over the client's proposed */
	SSL_CTX_set_options(ctx, SSL_OP_CIPHER_SERVER_PREFERENCE);

//	/* Enable OCSP stapling, include OCSP validation message in TLS hand-shake */
//	SSL_CTX_set_tlsext_status_type(ctx, TLSEXT_STATUSTYPE_ocsp);
//	SSL_CTX_set_tlsext_status_cb(ctx, ocsp_status_cb);

 	SSL_CTX_set_default_verify_paths(ctx);
 	SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);

	if (SSL_CTX_use_certificate_file(ctx, cert, SSL_FILETYPE_PEM) != 1) {
		syslog(LOG_ERR, "Invalid SSL cert '%s'", cert);
		goto error;
	}

	if (SSL_CTX_use_PrivateKey_file(ctx, key, SSL_FILETYPE_PEM) != 1) {
		syslog(LOG_ERR, "Invalid SSL key '%s'", key);
		goto error;
	}

	if (dhparm) {
		FILE *fp;
		DH *dh = NULL;

		fp = fopen(dhparm, "r");
		if (!fp) {
			syslog(LOG_ERR, "Failed opening dhfile %s: %s",
			       dhparm, strerror(errno));
			return ctx;
		}

		dh = PEM_read_DHparams(fp, NULL, NULL, NULL);
		fclose(fp);
		if (!dh || SSL_CTX_set_tmp_dh(ctx, dh) != 1)
			httpd_ssl_log_errors();
	}

	return ctx;
error:
	SSL_CTX_free(ctx);
	return NULL;
}

void httpd_ssl_exit(struct httpd *hs)
{
	if (!hs || !hs->ctx)
		return;

	SSL_CTX_free(hs->ctx);
	hs->ctx = NULL;

	ENGINE_cleanup();
	CRYPTO_cleanup_all_ex_data();
	CONF_modules_free();
	CONF_modules_unload(1);
	COMP_zlib_cleanup();
}

/*
 * Translates OpenSSL error code/status to human readable text.
 * Skips prototol (hacking) errors, connection reset, and the
 * odd cases where SSL_ERROR_SYSCALL and errno is unset.
 */
static int status(struct http_conn *hc, int rc)
{
	static char errmsg[80];

	hc->errmsg = NULL;
	if (rc > 0)
		return 0;

	rc = SSL_get_error(hc->ssl, rc);
	switch (rc) {
	case SSL_ERROR_SSL:	          /* rc = 1 */
		errno = EPROTO;
		goto leave;

	case SSL_ERROR_WANT_READ:         /* rc = 2 */
	case SSL_ERROR_WANT_WRITE:        /* rc = 3 */
	case SSL_ERROR_WANT_X509_LOOKUP:  /* rc = 4 */
	case SSL_ERROR_WANT_CONNECT:      /* rc = 7 */
	case SSL_ERROR_WANT_ACCEPT:       /* rc = 8 */
		errno = EAGAIN;
		break;

	case SSL_ERROR_SYSCALL:	          /* rc = 5 */
		/* errno set already. */
		if (errno != 0 && errno != ECONNRESET && errno != EPROTO)
			hc->errmsg = strerror(errno);
		goto leave;

	default:
		errno = EINVAL;
		break;
	}

	if (!hc->errmsg) {
		snprintf(errmsg, sizeof(errmsg), "%s, code %d",
			 ERR_reason_error_string(rc) ?: "unknown error", rc);
		hc->errmsg = errmsg;
	}

leave:
	return -1;
}

/*
** Poll underlying fd and call SSL_accept() as long as it
** wants more ... or until our patience runs out.
*/
static int accept_connection(struct http_conn *hc)
{
	struct pollfd pfd = {
		.events = POLLIN,
		.fd     = hc->conn_fd,
	};
	int rc, retries = 5;

retry:
	rc = poll(&pfd, 1, 100);
	if (rc > 0) {
		rc = status(hc, SSL_accept(hc->ssl));
		if (-1 == rc && EAGAIN == errno)
			goto retry;

		return rc;
	}

	if (rc < 0) {
		hc->errmsg = strerror(errno);
		return -1;
	}

	if (--retries > 0)
		goto retry;

	hc->errmsg = "client timeout";

	return -1;
}

static int set_nonblocking(int sd)
{
	int flags;

	flags  = fcntl(sd, F_GETFL, 0);
	if (-1 == flags)
		goto fail;

	flags |= O_NONBLOCK;
	if (-1 == fcntl(sd, F_SETFL, flags)) {
	fail:
		syslog(LOG_ERR, "Failed setting SSL socket non-blocking: %s",
		       strerror(errno));
	}

	return sd;
}

int httpd_ssl_open(struct http_conn *hc)
{
	SSL_CTX *ctx = NULL;

	if (!hc) {
		errno = EINVAL;
		return -1;
	}

	hc->ssl = NULL;
	if (hc->hs)
		ctx = hc->hs->ctx;

	if (ctx) {
		hc->ssl = SSL_new(ctx);
		if (!hc->ssl) {
			hc->errmsg = "creating connection";
			return 1;
		}

		SSL_set_fd(hc->ssl, set_nonblocking(hc->conn_fd));
		if (-1 == accept_connection(hc)) {
			ERR_clear_error();
			SSL_free(hc->ssl);

			return 1;
		}
	}

	return 0;
}

void httpd_ssl_close(struct http_conn *hc)
{
	if (hc->ssl)
		SSL_free(hc->ssl);
	hc->ssl = NULL;
}

void httpd_ssl_shutdown(struct http_conn *hc)
{
	if (hc->ssl)
		SSL_shutdown(hc->ssl);
}

static int ssl_error_cb(const char *str, size_t len, void *data)
{
	size_t sz;
	char buf[512];

	memset(buf, 0, sizeof(buf));
	sz = len < sizeof(buf) ? len : sizeof(buf) - 1;
	memcpy(buf, str, sz);

	syslog(LOG_DEBUG, "OpenSSL error: %s", buf);

	return 0;
}

void httpd_ssl_log_errors(void)
{
	ERR_print_errors_cb(ssl_error_cb, NULL);
}

ssize_t httpd_ssl_read(struct http_conn *hc, void *buf, size_t len)
{
	if (status(hc, SSL_read(hc->ssl, buf, len)))
		return -1;

	return len;
}

ssize_t httpd_ssl_write(struct http_conn *hc, void *buf, size_t len)
{
	if (status(hc, SSL_write(hc->ssl, buf, len)))
		return -1;

	return len;
}

ssize_t httpd_ssl_writev(struct http_conn *hc, struct iovec *iov, size_t num)
{
	size_t i, pos = 0, len = 0;
	char *buf;
	int rc;

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

	if (status(hc, rc))
		return -1;

	return len;
}
