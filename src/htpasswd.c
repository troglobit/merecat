/*
 * htpasswd.c: simple program for manipulating password file for NCSA httpd
 * 
 * Rob McCool
 */

/* Modified 29aug97 by Jef Poskanzer to accept new password on stdin,
** if stdin is a pipe or file.  This is necessary for use from CGI.
*/

#include <config.h>

#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

extern char *crypt(const char *key, const char *setting);

#define LF 10
#define CR 13

#define MAX_STRING_LEN 256

int tfd;
char tmp[] = "/tmp/htp.XXXXXX";

static char *strd(char *s)
{
	char *d;

	d = (char *)malloc(strlen(s) + 1);
	strcpy(d, s);

	return d;
}

static void getword(char *word, char *line, char stop)
{
	int x = 0, y;

	for (x = 0; ((line[x]) && (line[x] != stop)); x++)
		word[x] = line[x];

	word[x] = '\0';
	if (line[x])
		++x;
	y = 0;

	while ((line[y++] = line[x++]))
		;
}

static int get_line(char *s, int n, FILE *f)
{
	int i = 0;

	while (1) {
		s[i] = (char)fgetc(f);

		if (s[i] == CR)
			s[i] = fgetc(f);

		if ((s[i] == 0x4) || (s[i] == LF) || (i == (n - 1))) {
			s[i] = '\0';
			return (feof(f) ? 1 : 0);
		}
		++i;
	}
}

static void putline(FILE *f, char *l)
{
	int x;

	for (x = 0; l[x]; x++)
		fputc(l[x], f);
	fputc('\n', f);
}


/* From local_passwd.c (C) Regents of Univ. of California blah blah */
static unsigned char itoa64[] =	/* 0 ... 63 => ascii - 64 */
    "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

static void to64(char *s, long v, size_t len)
{
	size_t i;

	for (i = 0; i <= len; i++) {
		*s++ = itoa64[v & 0x3f];
		v >>= 6;
	}
}

#ifdef MPE
/* MPE lacks getpass() and a way to suppress stdin echo.  So for now, just
issue the prompt and read the results with echo.  (Ugh). */

char *getpass(const char *prompt)
{

	static char password[81];

	fputs(prompt, stderr);
	gets((char *)&password);

	if (strlen((char *)&password) > 8) {
		password[8] = '\0';
	}

	return (char *)&password;
}
#endif

static void add_password(char *user, FILE *fp)
{
	char pass[100];
	char *pw;
	char *cpw;
	char salt[12] = "$1$"; /* Long enough for MD5 Crypt */
	size_t index = 3;
	size_t saltlen = 8;
	const char *md5 = "$1$JASka/..$pV3V31AdjgqQmjTbgTNVu/";

	/* Test if the system supports MD5 passwords */
	if (strcmp(crypt("123456", md5), md5)) {
		/* The system does not support MD5 crypt: reset to default crypt. */
		saltlen = 2;
		index = 0;
	}

	if (!isatty(fileno(stdin))) {
		if (!fgets(pass, sizeof(pass), stdin)) {
			fprintf(stderr, "Failed reading password from stdin: %s\n", strerror(errno));
			exit(1);
		}

		if (pass[strlen(pass) - 1] == '\n')
			pass[strlen(pass) - 1] = '\0';
		pw = pass;
	} else {
		pw = strd((char *)getpass("New password:"));
		if (strcmp(pw, (char *)getpass("Re-type new password:")) != 0) {
			fprintf(stderr, "They don't match, sorry.\n");
			if (tfd != -1)
				unlink(tmp);
			exit(1);
		}
	}

	srandom(time(NULL));
	to64(&salt[index], random(), saltlen);

	cpw = crypt(pw, salt);
	if (cpw)
		fprintf(fp, "%s:%s\n", user, cpw);
	else
		fprintf(stderr, "crypt() returned NULL, sorry\n");
}

static int activate_template(char *template, char *file)
{
	char *buf;
	FILE *in, *out;

	in = fopen(template, "r");
	if (!in)
		return 1;

	out = fopen(file, "w");
	if (!out) {
		fclose(in);
		return 1;
	}

	buf = malloc(BUFSIZ);
	if (!buf) {
		fclose(in);
		fclose(out);
		return 1;
	}

	while (fgets(buf, BUFSIZ, in))
		fputs(buf, out);

	free(buf);
	fclose(in);
	fclose(out);

	return 0;
}

static int usage(int code)
{
	fprintf(stderr, "Usage: htpasswd [-c] passwordfile username\n");
	fprintf(stderr, "The -c flag creates a new file.\n");

	return code;
}

static void interrupted(int signo)
{
	fprintf(stderr, "Interrupted.\n");
	if (tfd != -1)
		unlink(tmp);
	exit(1);
}

int main(int argc, char *argv[])
{
	int found;
	FILE *tfp, *f;
	char user[MAX_STRING_LEN];
	char pwfilename[MAX_STRING_LEN];
	char line[MAX_STRING_LEN];
	char l[MAX_STRING_LEN];
	char w[MAX_STRING_LEN];

	tfd = -1;
	signal(SIGINT, interrupted);
	if (argc == 4) {
		if (strcmp(argv[1], "-c"))
			return usage(1);

		if (!(tfp = fopen(argv[2], "w"))) {
			fprintf(stderr, "Could not open passwd file %s for writing.\n", argv[2]);
			perror("fopen");
			return 1;
		}

		if (strlen(argv[2]) > (sizeof(pwfilename) - 1)) {
			fprintf(stderr, "%s: filename is too long\n", argv[0]);
			return 1;
		}

		if (((strchr(argv[2], ';')) != NULL) || ((strchr(argv[2], '>')) != NULL)) {
			fprintf(stderr, "%s: filename contains an illegal character\n", argv[0]);
			return 1;
		}

		if (strlen(argv[3]) > (sizeof(user) - 1)) {
			fprintf(stderr, "%s: username is too long\n", argv[0]);
			return 1;
		}

		if ((strchr(argv[3], ':')) != NULL) {
			fprintf(stderr, "%s: username contains an illegal character\n", argv[0]);
			return 1;
		}

		printf("Adding password for %s.\n", argv[3]);
		add_password(argv[3], tfp);
		fclose(tfp);
		return 0;
	} else if (argc != 3)
		return usage(1);

	tfd = mkstemp(tmp);
	if (!(tfp = fdopen(tfd, "w"))) {
		fprintf(stderr, "Could not open temp file.\n");
		return 1;
	}

	if (strlen(argv[1]) > (sizeof(pwfilename) - 1)) {
		fprintf(stderr, "%s: filename is too long\n", argv[0]);
		return 1;
	}

	if (((strchr(argv[1], ';')) != NULL) || ((strchr(argv[1], '>')) != NULL)) {
		fprintf(stderr, "%s: filename contains an illegal character\n", argv[0]);
		return 1;
	}

	if (strlen(argv[2]) > (sizeof(user) - 1)) {
		fprintf(stderr, "%s: username is too long\n", argv[0]);
		return 1;
	}

	if ((strchr(argv[2], ':')) != NULL) {
		fprintf(stderr, "%s: username contains an illegal character\n", argv[0]);
		return 1;
	}

	if (!(f = fopen(argv[1], "r"))) {
		fprintf(stderr, "Could not open passwd file %s for reading.\n", argv[1]);
		fprintf(stderr, "Use -c option to create new one.\n");
		return 1;
	}
	strncpy(user, argv[2], sizeof(user) - 1);
	user[sizeof(user)-1] = '\0';

	found = 0;
	while (!(get_line(line, MAX_STRING_LEN, f))) {
		if (found || (line[0] == '#') || (!line[0])) {
			putline(tfp, line);
			continue;
		}

		strcpy(l, line);
		getword(w, l, ':');
		if (strcmp(user, w)) {
			putline(tfp, line);
			continue;
		}

		printf("Changing password for user %s\n", user);
		add_password(user, tfp);
		found = 1;
	}

	if (!found) {
		printf("Adding user %s\n", user);
		add_password(user, tfp);
	}

	fclose(f);
	fclose(tfp);

	if (activate_template(tmp, argv[1]))
		fprintf(stderr, "Failed writing to %s: %s\n", argv[1], strerror(errno));
	unlink(tmp);

	return 0;
}
