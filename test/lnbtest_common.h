/*
 * LibNetBlock - A library which blocks programs from accessing the network.
 *	-- unit test common functions - header file.
 *
 * Copyright (C) 2015-2024 Bogdan Drozdowski, bogdro (at) users . sourceforge . net
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

#ifndef LNBTEST_COMMON_HEADER
# define LNBTEST_COMMON_HEADER 1

# define _POSIX_C_SOURCE 200809L
# define _XOPEN_SOURCE 600
# define _LARGEFILE64_SOURCE 1
# define _GNU_SOURCE 1
# define _ATFILE_SOURCE 1
# define _BSD_SOURCE 1
# define _SVID_SOURCE 1
# define _DEFAULT_SOURCE 1
# define _ISOC11_SOURCE		/* aligned_alloc() */

#include "libnetblock.h"

# ifdef HAVE_CONFIG_H
#  include <config.h>
# endif

# include <stdio.h>

# ifdef HAVE_UNISTD_H
#  include <unistd.h>
# endif

# ifdef HAVE_ERRNO_H
#  include <errno.h>
# else
static int errno = -1;
# endif

# ifdef HAVE_STDLIB_H
#  include <stdlib.h>
# endif

# ifdef HAVE_STRING_H
#  if (!defined STDC_HEADERS) && (defined HAVE_MEMORY_H)
#   include <memory.h>
#  endif
#  include <string.h>
# endif

# ifdef HAVE_FCNTL_H
#  include <fcntl.h>
# else
#  define O_RDONLY	0
#  define O_WRONLY	1
#  define O_RDWR		2
#  define O_TRUNC	01000
# endif

# ifdef HAVE_SYS_TYPES_H
#  include <sys/types.h>
# endif

# include <check.h>

/* compatibility with older check versions */
# ifndef ck_abort
#  define ck_abort() ck_abort_msg(NULL)
#  define ck_abort_msg fail
#  define ck_assert(C) ck_assert_msg(C, NULL)
#  define ck_assert_msg fail_unless
# endif

# ifndef _ck_assert_int
#  define _ck_assert_int(X, O, Y) ck_assert_msg((X) O (Y), "Assertion '"#X#O#Y"' failed: "#X"==%d, "#Y"==%d", X, Y)
#  define ck_assert_int_eq(X, Y) _ck_assert_int(X, ==, Y)
#  define ck_assert_int_ne(X, Y) _ck_assert_int(X, !=, Y)
# endif

# ifndef _ck_assert_str
#  define _ck_assert_str(C, X, O, Y) ck_assert_msg(C, "Assertion '"#X#O#Y"' failed: "#X"==\"%s\", "#Y"==\"%s\"", X, Y)
#  define ck_assert_str_eq(X, Y) _ck_assert_str(!strcmp(X, Y), X, ==, Y)
#  define ck_assert_str_ne(X, Y) _ck_assert_str(strcmp(X, Y), X, !=, Y)
# endif

# define LNB_MAXHOSTLEN 16384
# if defined(__GNUC__) && __GNUC__ >= 3
#  define LNB_ALIGN(x) __attribute__((aligned(x)))
# else
#  define LNB_ALIGN(x)
# endif

# if (defined LNB_ENABLE_USERBANS) && (defined HAVE_GETENV) \
	&& (defined HAVE_STDLIB_H) && (defined HAVE_MALLOC)
#  define LNB_CAN_USE_BANS 1
# else
#  undef LNB_CAN_USE_BANS
# endif

# if (defined LNB_ENABLE_ENV) && (defined HAVE_STDLIB_H) && (defined HAVE_GETENV)
#  define LNB_CAN_USE_ENV 1
# else
#  undef LNB_CAN_USE_ENV
# endif

# define LNB_TEST_FILENAME "zz1"
# define LNB_TEST_FILE_LENGTH 3
# define LNB_LINK_FILENAME "zz1link"
# define LNB_TEST_BANNED_FILENAME "/etc/hosts"
# define LNB_TEST_BANNED_FILENAME_SHORT "hosts"
# define LNB_TEST_BANNED_LINKNAME "banlink"
# define LNB_UNIX_SOCK "stest.sock"
# define LNB_EXIT_VALUE (-222)

# define LNB_PROLOG_FOR_TEST() \
	puts(__func__)

# ifdef __cplusplus
extern "C" {
# endif

extern void lnbtest_prepare_banned_file LNB_PARAMS((void));
extern TCase * lnbtest_add_fixtures LNB_PARAMS((TCase * tests));

# ifdef __cplusplus
}
# endif

#endif /* LNBTEST_COMMON_HEADER */
