/*
 * LibNetBlock - A library which blocks programs from accessing the network.
 *	-- unit test common functions.
 *
 * Copyright (C) 2015-2022 Bogdan Drozdowski, bogdro (at) users . sourceforge . net
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
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#define _POSIX_C_SOURCE 200112L	/* posix_memalign() */
#define _XOPEN_SOURCE 600	/* brk(), sbrk() */
#define _LARGEFILE64_SOURCE 1
#define _GNU_SOURCE	1	/* fallocate() */
#define _ATFILE_SOURCE 1
#define _GNU_SOURCE	1
#define _DEFAULT_SOURCE
#define _ISOC11_SOURCE		/* aligned_alloc() */

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#if (defined HAVE_DLFCN_H) && ((defined HAVE_DLSYM) || (defined HAVE_LIBDL))
	/* need RTLD_NEXT and dlvsym(), so define _GNU_SOURCE */
# ifndef _GNU_SOURCE
#  define _GNU_SOURCE	1
# endif
# include <dlfcn.h>
# ifndef RTLD_NEXT
#  define RTLD_NEXT ((void *) -1l)
# endif
#else
# ifdef LNB_ANSIC
#  error Dynamic loading functions missing.
# endif
#endif

#include "libnetblock.h"
#include <check.h>
#include "lnbtest_common.h"

#ifdef HAVE_UNISTD_H
# include <unistd.h>
#endif

#include <stdio.h>

#ifdef HAVE_STRING_H
# if (!defined STDC_HEADERS) && (defined HAVE_MEMORY_H)
#  include <memory.h>
# endif
# include <string.h>
#endif

#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif

#ifdef HAVE_SYS_STAT_H
# include <sys/stat.h>
#endif

#ifdef HAVE_FCNTL_H
# include <fcntl.h>
#else
# define O_RDONLY	0
# define O_WRONLY	1
# define O_RDWR		2
# define O_TRUNC	01000
#endif

/* ======================================================= */

void lnbtest_prepare_banned_file (void)
{
	FILE *f = NULL;
	f = fopen (LNB_TEST_BANNED_FILENAME, "w");
	if ( f != NULL )
	{
		fwrite ("aaa", 1, LNB_TEST_FILE_LENGTH, f);
		fclose (f);
	}
}

/* ======================================================= */

/*
__attribute__ ((constructor))
static void setup_global(void) / * unchecked fixture * /
{
	*(void **) (&orig_write) = dlsym (RTLD_NEXT, "write");
	*(void **) (&orig_rename) = dlsym (RTLD_NEXT, "rename");
}
*/
/*
static void teardown_global(void)
{
}
*/

static void setup_test(void) /* checked */
{
	FILE *f = NULL;
	f = fopen (LNB_TEST_FILENAME, "w");
	if ( f != NULL )
	{
		fwrite ("aaa", 1, LNB_TEST_FILE_LENGTH, f);
		fclose (f);
	}
}

static void teardown_test(void)
{
	unlink(LNB_TEST_FILENAME);
	unlink(LNB_TEST_BANNED_FILENAME);
}

TCase * lnbtest_add_fixtures(TCase * tests)
{
	if ( tests != NULL )
	{
		tcase_add_checked_fixture(tests, &setup_test, &teardown_test);
		/*tcase_add_unchecked_fixture(tests, &setup_global, &teardown_global);*/
	}
	return tests;
}
