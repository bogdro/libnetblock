/*
 * A library library which blocks programs from accessing the network.
 *	-- public header file.
 *
 * Copyright (C) 2011 Bogdan Drozdowski, bogdandr (at) op.pl
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

#ifndef _LIBNETBLOCK_H
# define _LIBNETBLOCK_H 1

/* PARAMS is a macro used to wrap function prototypes, so that
        compilers that don't understand ANSI C prototypes still work,
        and ANSI C compilers can issue warnings about type mismatches. */
# undef PARAMS
# if defined (__STDC__) || defined (_AIX) \
	|| (defined (__mips) && defined (_SYSTYPE_SVR4)) \
	|| defined(WIN32) || defined(__cplusplus)
#  define PARAMS(protos) protos
#  define LNB_ANSIC
# else
#  define PARAMS(protos) ()
#  undef LNB_ANSIC
# endif


# ifdef __cplusplus
extern "C" {
# endif

/**
 * Enables the use of libnetblock by any program that calls this function.
 * Simply linking the program with libnetblock enables it.
 */
extern void libnetblock_enable PARAMS((void));

# ifdef __cplusplus
}
# endif

#endif	/* _LIBNETBLOCK_H */

