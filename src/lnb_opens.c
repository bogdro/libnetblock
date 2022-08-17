/*
 * A library library which blocks programs from accessing the network.
 *	-- file opening functions' replacements.
 *
 * Copyright (C) 2011-2021 Bogdan Drozdowski, bogdro (at) users . sourceforge . net
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

#include "lnb_cfg.h"

#define _LARGEFILE64_SOURCE 1
/*# define _FILE_OFFSET_BITS 64*/
#define _ATFILE_SOURCE 1

#ifdef HAVE_STDARG_H
# include <stdarg.h>
#else
# ifdef HAVE_VARARGS_H
#  include <varargs.h>
# endif
#endif

#include <stdio.h>

#ifdef HAVE_UNISTD_H
# include <unistd.h>	/* readlink() */
#endif

#ifdef HAVE_ERRNO_H
# include <errno.h>
#endif

#ifdef HAVE_STRING_H
# if (!defined STDC_HEADERS) && (defined HAVE_MEMORY_H)
#  include <memory.h>
# endif
# include <string.h>
#endif

#ifdef HAVE_SYS_STAT_H
# ifdef STAT_MACROS_BROKEN
#  if STAT_MACROS_BROKEN
#   error Stat macros broken. Change your C library.
#  endif
# endif
# include <sys/stat.h>
#endif

#include <stdio.h>

#include "lnb_priv.h"

#ifdef HAVE_FCNTL_H
# include <fcntl.h>	/* open*() */
#else
# ifdef __cplusplus
extern "C" {
# endif

extern int open LNB_PARAMS ((const char * const path, const int flags, ... ));
extern int open64 LNB_PARAMS ((const char * const path, const int flags, ... ));

# ifdef __cplusplus
}
# endif
#endif

#ifdef __cplusplus
extern "C" {
#endif

#ifndef HAVE_OPENAT
extern int openat LNB_PARAMS ((const int dirfd, const char * const pathname, const int flags, ...));
#endif
#ifndef HAVE_OPENAT64
extern int openat64 LNB_PARAMS ((const int dirfd, const char * const pathname, const int flags, ...));
#endif
/*
#ifndef HAVE_FOPEN64
extern FILE* fopen64 LNB_PARAMS ((const char * const name, const char * const mode));
#endif
#ifndef HAVE_FREOPEN64
extern FILE* freopen64 LNB_PARAMS ((const char * const path, const char * const mode, FILE * stream));
#endif
#ifndef HAVE_OPEN64
extern int open64 LNB_PARAMS ((const char * const path, const int flags, ... ));
#endif

#ifdef __cplusplus
}
#endif
*/

#ifdef TEST_COMPILE
# ifdef LNB_ANSIC
#  define WAS_LNB_ANSIC
# endif
# undef LNB_ANSIC
#endif

/* ======================================================= */

#ifndef LNB_ANSIC
static FILE* generic_fopen LNB_PARAMS((
	const char * const name, const char * const mode,
	const fp_cp_cp real_fopen));
#endif

static FILE*
generic_fopen (
#ifdef LNB_ANSIC
	const char * const name, const char * const mode,
	const fp_cp_cp real_fopen)
#else
	name, mode, real_fopen)
	const char * const name;
	const char * const mode;
	const fp_cp_cp real_fopen;
#endif
{
	LNB_MAKE_ERRNO_VAR(err);

	if ( real_fopen == NULL )
	{
		LNB_SET_ERRNO_MISSING();
		return NULL;
	}

	if ( name == NULL )
	{
		LNB_SET_ERRNO(err);
		return (*real_fopen) (name, mode);
	}

	if ( name[0] == '\0' /*strlen (name) == 0*/ )
	{
		LNB_SET_ERRNO(err);
		return (*real_fopen) (name, mode);
	}

	if ( (__lnb_check_prog_ban () != 0)
		|| (__lnb_get_init_stage () < LNB_INIT_STAGE_FULLY_INITIALIZED) )
	{
		LNB_SET_ERRNO(err);
		return (*real_fopen) (name, mode);
	}

	if ( __lnb_is_forbidden_file (name) != 0 )
	{
		LNB_SET_ERRNO_PERM();
		return NULL;
	}
	LNB_SET_ERRNO(err);
	return (*real_fopen) (name, mode);
}

/* ======================================================= */

#ifdef fopen64
# undef fopen64
#endif

FILE*
fopen64 (
#ifdef LNB_ANSIC
	const char * const name, const char * const mode)
#else
	name, mode)
	const char * const name;
	const char * const mode;
#endif
{
#if (defined __GNUC__) && (!defined fopen64)
# pragma GCC poison fopen64
#endif
	__lnb_main ();

#ifdef LNB_DEBUG
	fprintf (stderr, "libnetblock: fopen64(%s, %s)\n",
		(name == NULL)? "null" : name,
		(mode == NULL)? "null" : mode);
	fflush (stderr);
#endif
	return generic_fopen (name, mode, __lnb_real_fopen64_location ());
}

/* ======================================================= */

#ifdef fopen
# undef fopen
#endif

FILE*
fopen (
#ifdef LNB_ANSIC
	const char * const name, const char * const mode)
#else
	name, mode)
	const char * const name;
	const char * const mode;
#endif
{
#if (defined __GNUC__) && (!defined fopen)
# pragma GCC poison fopen
#endif
	__lnb_main ();

#ifdef LNB_DEBUG
	fprintf (stderr, "libnetblock: fopen(%s, %s)\n",
		(name == NULL)? "null" : name,
		(mode == NULL)? "null" : mode);
	fflush (stderr);
#endif
	return generic_fopen (name, mode, __lnb_real_fopen_location ());
}

/* ======================================================= */

#ifndef LNB_ANSIC
static FILE* generic_freopen LNB_PARAMS((
	const char * const name, const char * const mode, FILE * stream,
	const fp_cp_cp_fp real_freopen));
#endif

static FILE*
generic_freopen (
#ifdef LNB_ANSIC
	const char * const path, const char * const mode, FILE * stream,
	const fp_cp_cp_fp real_freopen)
#else
	path, mode, stream, real_freopen)
	const char * const path;
	const char * const mode;
	FILE * stream;
	const fp_cp_cp_fp real_freopen;
#endif
{
	LNB_MAKE_ERRNO_VAR(err);

	if ( real_freopen == NULL )
	{
		LNB_SET_ERRNO_MISSING();
		return NULL;
	}

	if ( path == NULL )
	{
		LNB_SET_ERRNO(err);
		return (*real_freopen) ( path, mode, stream );
	}

	if ( (path[0] == '\0') /*(strlen (path) == 0)*/
		/*|| (stream == stdin) || (stream == stdout) || (stream == stderr)*/
	   )
	{
		LNB_SET_ERRNO(err);
		return (*real_freopen) ( path, mode, stream );
	}

	if ( (__lnb_check_prog_ban () != 0)
		|| (__lnb_get_init_stage () < LNB_INIT_STAGE_FULLY_INITIALIZED) )
	{
		LNB_SET_ERRNO(err);
		return (*real_freopen) ( path, mode, stream );
	}

	if ( __lnb_is_forbidden_file (path) != 0 )
	{
		LNB_SET_ERRNO_PERM();
		if ( stream != NULL )
		{
			fclose (stream);
		}
		return NULL;
	}

	LNB_SET_ERRNO(err);
	return (*real_freopen) ( path, mode, stream );
}

/* ======================================================= */

#ifdef freopen64
# undef freopen64
#endif

FILE*
freopen64 (
#ifdef LNB_ANSIC
	const char * const name, const char * const mode, FILE * stream)
#else
	name, mode, stream)
	const char * const name;
	const char * const mode;
	FILE * stream;
#endif
{
#if (defined __GNUC__) && (!defined freopen64)
# pragma GCC poison freopen64
#endif
	__lnb_main ();

#ifdef LNB_DEBUG
	fprintf (stderr, "libnetblock: freopen64(%s, %s, %ld)\n",
		(name == NULL)? "null" : name,
		(mode == NULL)? "null" : mode,
		 (long int)stream);
	fflush (stderr);
#endif
	return generic_freopen (name, mode, stream,
		__lnb_real_freopen64_location ());

}

/* ======================================================= */

#ifdef freopen
# undef freopen
#endif

FILE*
freopen (
#ifdef LNB_ANSIC
	const char * const name, const char * const mode, FILE* stream)
#else
	name, mode, stream)
	const char * const name;
	const char * const mode;
	FILE* stream;
#endif
{
#if (defined __GNUC__) && (!defined freopen)
# pragma GCC poison freopen
#endif
	__lnb_main ();

#ifdef LNB_DEBUG
	fprintf (stderr, "libnetblock: freopen(%s, %s, %ld)\n",
		(name == NULL)? "null" : name,
		(mode == NULL)? "null" : mode,
		 (long int)stream);
	fflush (stderr);
#endif
	return generic_freopen (name, mode, stream,
		__lnb_real_freopen_location ());
}

/* ======================================================= */

#ifndef LNB_ANSIC
static int generic_open LNB_PARAMS((
	const char * const path, const int flags,
	const mode_t mode, const i_cp_i_ real_open));
#endif

static int
generic_open (
#ifdef LNB_ANSIC
	const char * const path, const int flags,
	const mode_t mode, const i_cp_i_ real_open)
#else
	path, flags, mode, real_open)
	const char * const path;
	const int flags;
	const mode_t mode;
	const i_cp_i_ real_open;
#endif
{
	LNB_MAKE_ERRNO_VAR(err);

	if ( real_open == NULL )
	{
		LNB_SET_ERRNO_MISSING();
		return -1;
	}

	if ( path == NULL )
	{
		LNB_SET_ERRNO(err);
		return (*real_open) ( path, flags, mode );
	}

	if ( path[0] == '\0' /*strlen (path) == 0*/ )
	{
		LNB_SET_ERRNO(err);
		return (*real_open) ( path, flags, mode );
	}

	if ( (__lnb_check_prog_ban () != 0)
		|| (__lnb_get_init_stage () < LNB_INIT_STAGE_FULLY_INITIALIZED) )
	{
		LNB_SET_ERRNO(err);
		return (*real_open) ( path, flags, mode );
	}

	if ( __lnb_is_forbidden_file (path) != 0 )
	{
		LNB_SET_ERRNO_PERM();
		return -1;
	}

	LNB_SET_ERRNO(err);
	return (*real_open) ( path, flags, mode );
}

/* ======================================================= */

#if (defined TEST_COMPILE) && (defined WAS_LNB_ANSIC)
# define LNB_ANSIC 1
#endif

/* 'man 2 open' gives:
    int open(const char *pathname, int flags);
    int open(const char *pathname, int flags, mode_t mode);
   'man 3p open' (POSIX) & /usr/include/fcntl.h give:
    int open(const char *path, int oflag, ...  );
 */

#ifdef open64
# undef open64
#endif

int
open64 (
#ifdef LNB_ANSIC
	const char * const path, const int flags, ... )
#else
	va_alist )
	va_dcl /* no semicolons here! */
	/*
	path, flags )
	const char * const path;
	const int flags;*/
#endif
{
#if (defined __GNUC__) && (!defined open64)
# pragma GCC poison open64
#endif

#if (defined HAVE_STDARG_H) || (defined HAVE_VARARGS_H)
	va_list args;
# ifndef LNB_ANSIC
	char * const path;
	int flags;
# endif
#endif
	int ret_fd;
	mode_t mode = 0666;
	LNB_MAKE_ERRNO_VAR(err);

	__lnb_main ();

#if (defined HAVE_STDARG_H) || (defined HAVE_VARARGS_H)
# ifdef LNB_ANSIC
	va_start (args, flags);
# else
	va_start (args);
	path = va_arg (args, char * const);
	flags = va_arg (args, int);
# endif
	if ( (flags & O_CREAT) != 0 )
	{
		mode = va_arg (args, mode_t);
	}
#endif

#ifdef LNB_DEBUG
	fprintf (stderr, "libnetblock: open64(%s, 0%o, ...)\n",
		(path == NULL)? "null" : path, flags);
	fflush (stderr);
#endif

	ret_fd = generic_open (path, flags, mode, __lnb_real_open64_location ());
#if (defined HAVE_STDARG_H) || (defined HAVE_VARARGS_H)
	LNB_GET_ERRNO(err);
	va_end (args);
	LNB_SET_ERRNO(err);
#endif
	return ret_fd;
}

/* ======================================================= */

#ifdef open
# undef open
#endif

int
open (
#ifdef LNB_ANSIC
	const char * const name, const int flags, ... )
#else
	va_alist )
	va_dcl /* no semicolons here! */
	/*
	name, flags )
	const char * const name;
	const int flags;*/
#endif
{
#if (defined __GNUC__) && (!defined open)
# pragma GCC poison open
#endif

#if (defined HAVE_STDARG_H) || (defined HAVE_VARARGS_H)
	va_list args;
# ifndef LNB_ANSIC
	char * const name;
	int flags;
# endif
#endif
	int ret_fd;
	mode_t mode = 0666;
	LNB_MAKE_ERRNO_VAR(err);

	__lnb_main ();

#if (defined HAVE_STDARG_H) || (defined HAVE_VARARGS_H)
# ifdef LNB_ANSIC
	va_start (args, flags);
# else
	va_start (args);
	name = va_arg (args, char * const);
	flags = va_arg (args, int);
# endif
	if ( (flags & O_CREAT) != 0 )
	{
		mode = va_arg (args, mode_t);
	}
#endif

#ifdef LNB_DEBUG
	fprintf (stderr, "libnetblock: open(%s, 0%o, ...)\n",
		(name == NULL)? "null" : name, flags);
	fflush (stderr);
#endif

	ret_fd = generic_open (name, flags, mode, __lnb_real_open_location ());
#if (defined HAVE_STDARG_H) || (defined HAVE_VARARGS_H)
	LNB_GET_ERRNO(err);
	va_end (args);
	LNB_SET_ERRNO(err);
#endif
	return ret_fd;
}

/* ======================================================= */

#ifdef TEST_COMPILE
# undef LNB_ANSIC
#endif

#ifndef LNB_ANSIC
static int generic_openat LNB_PARAMS((
	const int dirfd, const char * const path, const int flags,
	const mode_t mode, const i_i_cp_i_ real_openat));
#endif

static int
generic_openat (
#ifdef LNB_ANSIC
	const int dirfd, const char * const pathname, const int flags,
	const mode_t mode, const i_i_cp_i_ real_openat)
#else
	dirfd, pathname, flags, mode, real_openat)
	const int dirfd;
	const char * const pathname;
	const int flags;
	const mode_t mode;
	const i_i_cp_i_ real_openat;
#endif
{
	LNB_MAKE_ERRNO_VAR(err);

	if ( real_openat == NULL )
	{
		LNB_SET_ERRNO_MISSING();
		return -1;
	}

	if ( pathname == NULL )
	{
		LNB_SET_ERRNO(err);
		return (*real_openat) ( dirfd, pathname, flags, mode );
	}

	if ( pathname[0] == '\0' /*strlen (pathname) == 0*/ )
	{
		LNB_SET_ERRNO(err);
		return (*real_openat) ( dirfd, pathname, flags, mode );
	}

	if ( (__lnb_check_prog_ban () != 0)
		|| (__lnb_get_init_stage () < LNB_INIT_STAGE_FULLY_INITIALIZED) )
	{
		LNB_SET_ERRNO(err);
		return (*real_openat) ( dirfd, pathname, flags, mode );
	}

	if ( __lnb_is_forbidden_file (pathname) != 0 )
	{
		LNB_SET_ERRNO_PERM();
		return -1;
	}

	LNB_SET_ERRNO(err);
	return (*real_openat) ( dirfd, pathname, flags, mode );
}

/* ======================================================= */

#if (defined TEST_COMPILE) && (defined WAS_LNB_ANSIC)
# define LNB_ANSIC 1
#endif

#ifdef openat64
# undef openat64
#endif

int
openat64 (
#ifdef LNB_ANSIC
	const int dirfd, const char * const pathname, const int flags, ...)
#else
	va_alist )
	va_dcl /* no semicolons here! */
	/*
	dirfd, pathname, flags )
	const int dirfd;
	const char * const pathname;
	const int flags;*/
#endif
{
#if (defined __GNUC__) && (!defined openat64)
# pragma GCC poison openat64
#endif

	int ret_fd;
	mode_t mode = 0666;
#if (defined HAVE_STDARG_H) || (defined HAVE_VARARGS_H)
	va_list args;
# ifndef LNB_ANSIC
	int dirfd;
	char * const pathname;
	int flags;
# endif
#endif
	LNB_MAKE_ERRNO_VAR(err);

	__lnb_main ();

#if (defined HAVE_STDARG_H) || (defined HAVE_VARARGS_H)
# ifdef LNB_ANSIC
	va_start (args, flags);
# else
	va_start (args);
	dirfd = va_arg (args, int);
	pathname = va_arg (args, char * const);
	flags = va_arg (args, int);
# endif
	if ( (flags & O_CREAT) != 0 )
	{
		mode = va_arg (args, mode_t);
	}
#endif
#ifdef LNB_DEBUG
	fprintf (stderr, "libnetblock: openat64(%d, %s, 0%o, ...)\n",
		dirfd, (pathname == NULL)? "null" : pathname, flags);
	fflush (stderr);
#endif

	ret_fd = generic_openat (dirfd, pathname, flags, mode,
		__lnb_real_openat64_location ());
#if (defined HAVE_STDARG_H) || (defined HAVE_VARARGS_H)
	LNB_GET_ERRNO(err);
	va_end (args);
	LNB_SET_ERRNO(err);
#endif

	return ret_fd;
}


/* ======================================================= */

/*/
int openat(int dirfd, const char *pathname, int flags);
int openat(int dirfd, const char *pathname, int flags, mode_t mode);
 */

#ifdef openat
# undef openat
#endif

int
openat (
#ifdef LNB_ANSIC
	const int dirfd, const char * const pathname, const int flags, ...)
#else
	va_alist )
	va_dcl /* no semicolons here! */
	/*
	dirfd, pathname, flags )
	const int dirfd;
	const char * const pathname;
	const int flags;*/
#endif
{
#if (defined __GNUC__) && (!defined openat)
# pragma GCC poison openat
#endif

	int ret_fd;
	mode_t mode = 0666;
#if (defined HAVE_STDARG_H) || (defined HAVE_VARARGS_H)
	va_list args;
# ifndef LNB_ANSIC
	int dirfd;
	char * const pathname;
	int flags;
# endif
#endif
	LNB_MAKE_ERRNO_VAR(err);

	__lnb_main ();

#if (defined HAVE_STDARG_H) || (defined HAVE_VARARGS_H)
# ifdef LNB_ANSIC
	va_start (args, flags);
# else
	va_start (args);
	dirfd = va_arg (args, int);
	pathname = va_arg (args, char * const);
	flags = va_arg (args, int);
# endif
	if ( (flags & O_CREAT) != 0 )
	{
		mode = va_arg (args, mode_t);
	}
#endif
#ifdef LNB_DEBUG
	fprintf (stderr, "libnetblock: openat(%d, %s, 0%o, ...)\n", dirfd,
		(pathname == NULL)? "null" : pathname, flags);
	fflush (stderr);
#endif

	ret_fd = generic_openat (dirfd, pathname, flags, mode,
		__lnb_real_openat_location ());
#if (defined HAVE_STDARG_H) || (defined HAVE_VARARGS_H)
	LNB_GET_ERRNO(err);
	va_end (args);
	LNB_SET_ERRNO(err);
#endif

	return ret_fd;
}
