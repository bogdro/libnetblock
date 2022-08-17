/*
 * A library library which blocks programs from accessing the network.
 *	-- unit test for banning functions.
 *
 * Copyright (C) 2015-2019 Bogdan Drozdowski, bogdandr (at) op.pl
 * License: GNU General Public License, v3+
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 3
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software Foudation:
 *		Free Software Foundation
 *		51 Franklin Street, Fifth Floor
 *		Boston, MA 02110-1301
 *		USA
 */

#define _POSIX_C_SOURCE 200112L
#define _XOPEN_SOURCE 600
#define _LARGEFILE64_SOURCE 1
#define _BSD_SOURCE 1
#define _SVID_SOURCE 1
#define _DEFAULT_SOURCE 1

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include "libnetblock.h"
#include <check.h>
#include "lnbtest_common.h"

#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif

#ifdef HAVE_ERRNO_H
# include <errno.h>
#else
static int errno = -1;
#endif

#ifdef HAVE_MALLOC_H
# include <malloc.h>
#endif

#ifdef HAVE_UNISTD_H
# include <unistd.h>
#endif

#include <stdio.h>

#ifdef HAVE_STDLIB_H
# include <stdlib.h>
#endif

#ifdef HAVE_STRING_H
# if (!defined STDC_HEADERS) && (defined HAVE_MEMORY_H)
#  include <memory.h>
# endif
# include <string.h>
#endif

#ifdef HAVE_FCNTL_H
# include <fcntl.h>
#else
# define O_RDONLY	0
# define O_WRONLY	1
# define O_RDWR		2
# define O_TRUNC	01000
#endif

/* ========================================================== */

#ifdef LNB_CAN_USE_BANS
START_TEST(test_banned_in_userfile_prog)
{
	int fd;
	FILE * user_ban_file;
	char * user_ban_file_name;
	char * home_env;
	int err;
	long file_len;

	printf("test_banned_in_userfile_prog\n");

	home_env = getenv("HOME");
	if ( home_env == NULL )
	{
		return;
	}
	user_ban_file_name = (char *) malloc (strlen (home_env) + 1
		+ strlen (LNB_BANNING_USERFILE) + 1);
	if ( user_ban_file_name == NULL )
	{
		fail("test_banned_in_userfile_prog: cannot allocate memory: errno=%d\n", errno);
	}
	strcpy (user_ban_file_name, home_env);
	strcat (user_ban_file_name, "/");
	strcat (user_ban_file_name, LNB_BANNING_USERFILE);

	user_ban_file = fopen (user_ban_file_name, "a+");
	if ( user_ban_file == NULL )
	{
		err = errno;
		free (user_ban_file_name);
		fail("test_banned_in_userfile_prog: cannot open user file: errno=%d\n", err);
	}

	fseek (user_ban_file, 0, SEEK_END);
	file_len = ftell (user_ban_file);
	fwrite ("\nlnbtest\n", 1, strlen("\nlnbtest\n"), user_ban_file);
	fclose (user_ban_file);

	fd = open(LNB_TEST_FILENAME, O_WRONLY | O_TRUNC);
	err = errno;
	if ( file_len == 0 )
	{
		unlink (user_ban_file_name);
	}
	else
	{
		truncate (user_ban_file_name, file_len);
	}
	if (fd >= 0)
	{
		close(fd);
	}
	else
	{
		free (user_ban_file_name);
		fail("test_banned_in_userfile_prog: file not opened: errno=%d\n", err);
	}
	free (user_ban_file_name);
}
END_TEST
#endif

#ifdef LNB_CAN_USE_ENV
START_TEST(test_banned_in_env_prog)
{
	int fd;
	FILE * env_ban_file;
	char env_ban_file_name[] = "libnetblock.env";
	int err;
	long file_len;
	int res;

	printf("test_banned_in_env_prog\n");

	res = setenv(LNB_BANNING_ENV, env_ban_file_name, 1);
	if ( res != 0 )
	{
		fail("test_banned_in_env_prog: cannot set environment: errno=%d\n", errno);
	}

	env_ban_file = fopen (env_ban_file_name, "a+");
	if ( env_ban_file == NULL )
	{
		unsetenv(LNB_BANNING_ENV);
		fail("test_banned_in_env_prog: cannot open user file: errno=%d\n", errno);
	}

	fseek (env_ban_file, 0, SEEK_END);
	file_len = ftell (env_ban_file);
	fwrite ("\nlnbtest\n", 1, strlen("\nlnbtest\n"), env_ban_file);
	fclose (env_ban_file);

	fd = open(LNB_TEST_FILENAME, O_WRONLY | O_TRUNC);
	err = errno;
	if ( file_len == 0 )
	{
		unlink (env_ban_file_name);
	}
	else
	{
		truncate (env_ban_file_name, file_len);
	}
	if (fd >= 0)
	{
		close(fd);
	}
	else
	{
		unsetenv(LNB_BANNING_ENV);
		fail("test_banned_in_env_prog: file not opened: errno=%d\n", err);
	}
}
END_TEST
#endif

/* ========================================================== */

/*
__attribute__ ((constructor))
static void setup_global(void) / * unchecked * /
{
}
*/

/*
static void teardown_global(void)
{
}
*/

static void setup_file_test(void) /* checked */
{
	FILE *f;

	f = fopen(LNB_TEST_FILENAME, "w");
	if (f != NULL)
	{
		fwrite("aaa", 1, LNB_TEST_FILE_LENGTH, f);
		fclose(f);
	}
}

static void teardown_file_test(void)
{
	unlink(LNB_TEST_FILENAME);
}

static Suite * lnb_create_suite(void)
{
	Suite * s = suite_create("libnetblock");

	TCase * tests_banned = tcase_create("banning");

#ifdef LNB_CAN_USE_BANS
	tcase_add_test(tests_banned, test_banned_in_userfile_prog);
#endif
#ifdef LNB_CAN_USE_ENV
	tcase_add_test(tests_banned, test_banned_in_env_prog);
#endif

	tcase_add_checked_fixture(tests_banned, &setup_file_test, &teardown_file_test);

	/* set 30-second timeouts */
	tcase_set_timeout(tests_banned, 30);

	suite_add_tcase(s, tests_banned);

	return s;
}

int main(void)
{
	int failed = 0;

	Suite * s = lnb_create_suite();
	SRunner * sr = srunner_create(s);

	srunner_run_all(sr, CK_NORMAL);

	failed = srunner_ntests_failed(sr);
	srunner_free(sr);

	return failed;
}
