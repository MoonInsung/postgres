/*-------------------------------------------------------------------------
 *
 * pg_keygen.c
 *
 * Copyright (c) 2010-2019, PostgreSQL Global Development Group
 *
 * IDENTIFICATION
 *	  src/bin/pg_keygen/pg_keygen.c
 *
 *-------------------------------------------------------------------------
 */

#include "postgres_fe.h"

#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>


#include "common/file_perm.h"
#include "common/file_utils.h"
#include "common/logging.h"
#include "getopt_long.h"
#include "pg_getopt.h"

#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#ifdef HAVE_OPENSSL_KDF
#include <openssl/kdf.h>
#endif

#define DEFAULT_INTERATION_COUNT 100000

static int interCount = DEFAULT_INTERATION_COUNT;
static char *encCipher = "aes-128";
static char *password = NULL;
static char *passwordFile = NULL;
static int	keySize;

static const char *progname;

static void
usage(void)
{
	printf(_("%s generate cluster encryption key for PostgreSQL database cluster.\n\n"), progname);
	printf(_("Usage:\n"));
	printf(_("  %s [OPTION]... [DATADIR]\n"), progname);
	printf(_("\nOptions:\n"));
	printf(_("  -p, --password           password to generate encryption key\n"));
	printf(_("  -P, --password-file      file contains password to generate encryption key\n"));
	printf(_("  -i, --iter               Specify the iteration count and force use of PBKDF2\n"));
	printf(_("  -e, --enc-cipher         encryption cipher for data encryption\n"));
	printf(_("  -?, --help               show this help, then exit\n"));
	printf(_("\nIf no data directory (DATADIR) is specified, "
			 "the environment variable PGDATA\nis used.\n\n"));
	printf(_("Report bugs to <pgsql-bugs@lists.postgresql.org>.\n"));
}

int
main(int argc, char *argv[])
{
	unsigned char	*derived_key;
	int				ret;
	int				c;
	int				option_index;
	static struct option long_options[] = {
		{"password", required_argument, NULL, 'p'},
		{"password-file", required_argument, NULL, 'P'},
		{"iter", required_argument, NULL, 'i'},
		{"enc-cipher",required_argument, NULL, 'e'},
		{NULL, 0, NULL, 0}
	};

#ifndef USE_OPENSSL
	pg_log_error("pg_keygen is not supported because OpenSSL is not supported by this build");
	exit(1);
#endif

	pg_logging_init(argv[0]);
	set_pglocale_pgservice(argv[0], PG_TEXTDOMAIN("pg_keygen"));
	progname = get_progname(argv[0]);

	if (argc > 1)
	{
		if (strcmp(argv[1], "--help") == 0 || strcmp(argv[1], "-?") == 0)
		{
			usage();
			exit(0);
		}
		if (strcmp(argv[1], "--version") == 0 || strcmp(argv[1], "-V") == 0)
		{
			puts("pg_keygen (PostgreSQL) " PG_VERSION);
			exit(0);
		}
	}

	while ((c = getopt_long(argc, argv, "p:P:i:e:", long_options, &option_index)) != -1)
	{
		switch (c)
		{
			case 'p':
				password = pstrdup(optarg);
				break;
			case 'P':
				passwordFile = pstrdup(optarg);
				break;
			case 'i':
				interCount = atoi(optarg);
				break;
			case 'e':
				encCipher = pg_strdup(optarg);
				break;
			default:
				fprintf(stderr, _("Try \"%s --help\" for more information.\n"), progname);
				exit(1);
		}
	}

	if (password == NULL && passwordFile == NULL)
	{
		pg_log_error("no password specified");
		exit(1);
	}

	if (password != NULL && passwordFile != NULL)
	{
		pg_log_error("msut be either password(-p) or passwor file (-P) specified");
		exit(1);
	}

	if (interCount <= 0)
	{
		pg_log_error("interation count(-i) must be more than 0");
		exit(1);
	}

	/* Verify encryption cipher and get key size */
	if (strncmp(encCipher, "aes-128", 7) == 0)
		keySize = 16;
	else if (strncmp(encCipher, "aes-256", 7) == 0)
		keySize = 32;
	else
	{
		pg_log_error("invalid encryption cipher \"%s\"", encCipher);
		exit(1);
	}

	derived_key = pg_malloc(keySize + 1);

	if (passwordFile)
	{
		int		fd;
		int		r;
		char	buf[1024];

		fd = open(passwordFile, PG_BINARY, 0);

		if (fd < 0)
		{
			pg_log_error("could not open file \"%s\": %m", passwordFile);
			exit(1);
		}

		r = read(fd, buf, 1024);

		if (r < 0)
		{
			pg_log_error("could not read file \"%s\": %m", passwordFile);
			exit(1);
		}

		password = pg_malloc(r + 1);
		memcpy(password, buf, r);
		password[r] = '\0';
	}

	ret = PKCS5_PBKDF2_HMAC(password, strlen(password), (unsigned char *)"hoge", 4,
							interCount,
							keySize == 16 ? EVP_md5() : EVP_sha256(),
							keySize, derived_key);
	if (ret != 1)
	{
		pg_log_error("could not derive encryption key from password");
		exit(1);
	}

	derived_key[keySize] = '\0';

	printf("%s", derived_key);

	return 0;
}
