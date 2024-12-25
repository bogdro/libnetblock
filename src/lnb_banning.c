/*
 * LibNetBlock - A library which blocks programs from accessing the network.
 *	-- private file and program banning functions.
 *
 * Copyright (C) 2011-2024 Bogdan Drozdowski, bogdro (at) users . sourceforge . net
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

#include "lnb_cfg.h"
#include "lnb_paths.h"

#include <stdio.h>

#ifdef HAVE_STRING_H
# if (!defined STDC_HEADERS) && (defined HAVE_MEMORY_H)
#  include <memory.h>
# endif
# include <string.h>
#endif

#include "lnb_priv.h"
#include "libnetblock.h"

#if (defined LNB_ENABLE_USERBANS) && (defined HAVE_GETENV) \
	&& (defined HAVE_STDLIB_H) && (defined HAVE_MALLOC)
# define LNB_CAN_USE_BANS 1
# define BANNING_CAN_USE_BANS 1
#else
# undef LNB_CAN_USE_BANS
# define BANNING_CAN_USE_BANS 0
#endif

#if (defined LNB_ENABLE_ENV) && (defined HAVE_STDLIB_H) && (defined HAVE_GETENV)
# define LNB_CAN_USE_ENV 1
# define BANNING_ENABLE_ENV 1
#else
# undef LNB_CAN_USE_ENV
# define BANNING_ENABLE_ENV 0
#endif

#ifdef TEST_COMPILE
# undef LNB_ANSIC
#endif

#ifdef LNB_ANSIC
# define BANNING_ANSIC 1
#else
# define BANNING_ANSIC 0
#endif

#define BANNING_SET_ERRNO(value) LNB_SET_ERRNO(value)
#define BANNING_GET_ERRNO(value) LNB_GET_ERRNO(variable)
#define BANNING_MAKE_ERRNO_VAR(x) LNB_MAKE_ERRNO_VAR(x)
#define BANNING_MAXPATHLEN LNB_MAXPATHLEN
#define BANNING_PATH_SEP LNB_PATH_SEP
#define BANNING_MKNAME(x) __lnb ## x
#define BANNING_PARAMS(x) LNB_PARAMS(x)

#ifndef HAVE_READLINK
# define HAVE_READLINK 0
#endif
#ifndef HAVE_GETENV
# define HAVE_GETENV 0
#endif

#include <banning-generic.c>

#if HAVE_READLINK == 0
# undef HAVE_READLINK
#endif
#if HAVE_GETENV == 0
# undef HAVE_GETENV
#endif

/* =============================================================== */

int GCC_WARN_UNUSED_RESULT
__lnb_check_prog_ban (LNB_VOID)
{
	int	ret = 0;	/* DEFAULT: NO, this program is not banned */
	LNB_MAKE_ERRNO_VAR(err);

	/* Is this process on the list of applications to ignore? */
	__banning_get_exename (__banning_exename, LNB_MAXPATHLEN);
	__banning_exename[LNB_MAXPATHLEN-1] = '\0';
#ifdef LNB_DEBUG
	fprintf (stderr, "libnetblock: __lnb_check_prog_ban(): exename='%s'\n",
		__banning_exename);
	fflush (stderr);
#endif

	if ( __banning_exename[0] == '\0' /*strlen (__banning_exename) == 0*/ )
	{
		/* can't find executable name. Assume not banned */
		LNB_SET_ERRNO (err);
		return 0;
	}

	ret = __banning_is_banned ("libnetblock.progban",
		LNB_BANNING_USERFILE, LNB_BANNING_ENV,
		__banning_exename);
#ifdef LNB_DEBUG
	fprintf (stderr, "libnetblock: __lnb_check_prog_ban()=%d\n", ret);
	fflush (stderr);
#endif
	LNB_SET_ERRNO (err);
	return ret;
}
