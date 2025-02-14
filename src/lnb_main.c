/*
 * LibNetBlock - A library which blocks programs from accessing the network.
 *
 * Copyright (C) 2011-2024 Bogdan Drozdowski, bogdro (at) users . sourceforge . net
 * Parts of this file are Copyright (C) Free Software Foundation, Inc.
 * License: GNU General Public License, v3+
 *
 * Syntax example: export LD_PRELOAD=/usr/local/lib/libnetblock.so
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

#include <stddef.h>

#ifdef HAVE_STRING_H
# if (!defined STDC_HEADERS) && (defined HAVE_MEMORY_H)
#  include <memory.h>
# endif
# include <string.h>
#endif

#include "lnb_priv.h"

static int	__lnb_is_initialized		= LNB_INIT_STAGE_NOT_INITIALIZED;

/* --- Pointers to original functions. */
/* program execution functions: */
static i_cp_cpp_cpp			__lnb_real_execve		= NULL;
static i_i_cpp_cpp			__lnb_real_fexecve		= NULL;
static i_i_cp_cpp_cpp_i			__lnb_real_execveat		= NULL;
static i_cp				__lnb_real_system		= NULL;

/* network-related functions: */
static i_i_i_i				__lnb_real_socket		= NULL;
static ss_i_smp_i			__lnb_real_recvmsg		= NULL;
static ss_i_csmp_i			__lnb_real_sendmsg		= NULL;
static i_cssp_sl			__lnb_real_bind			= NULL;
static i_i_ssa				__lnb_real_bindresvport		= NULL;
static i_i_ssa6				__lnb_real_bindresvport6	= NULL;

/* file-related functions: */
static fp_cp_cp				__lnb_real_fopen64		= NULL;
static fp_cp_cp_fp			__lnb_real_freopen64		= NULL;
static i_cp_i_				__lnb_real_open64		= NULL;
static i_i_cp_i_			__lnb_real_openat64		= NULL;
static fp_cp_cp				__lnb_real_fopen		= NULL;
static fp_cp_cp_fp			__lnb_real_freopen		= NULL;
static i_cp_i_				__lnb_real_open			= NULL;
static i_i_cp_i_			__lnb_real_openat		= NULL;

/* libpcap functions: */
static pp_ccp_cp			__lnb_real_pcap_create		= NULL;
static pp_ccp_i_i_i_cp			__lnb_real_pcap_open_live	= NULL;

#ifdef LNB_CANT_USE_VERSIONED_FOPEN
# undef LNB_CANT_USE_VERSIONED_FOPEN
#endif
#if ((defined HAVE_DLSYM) || (defined HAVE_LIBDL_DLSYM))		\
	&& (!defined HAVE_DLVSYM) && (!defined HAVE_LIBDL_DLVSYM)	\
	|| (defined __GLIBC__ && (__GLIBC__ < 2 || (__GLIBC__ == 2 && __GLIBC_MINOR__ < 1)))
# define LNB_CANT_USE_VERSIONED_FOPEN 1
/*# warning Versioned fopen is unavailable, so LibNetBlock may crash on some glibc versions.*/
#endif

#ifdef TEST_COMPILE
# undef LNB_ANSIC
# if TEST_COMPILE > 1
#  undef HAVE_MALLOC
# endif
#endif

/* =============================================================== */

void __lnb_copy_string (
#ifdef LNB_ANSIC
	char * const dest, const char src[], const size_t len)
#else
	dest, src, len)
	char * const dest;
	const char src[];
	const size_t len;
#endif
{
#ifndef HAVE_STRING_H
	size_t i;
#endif
	if ( (src == NULL) || (dest == NULL) )
	{
		return;
	}
#ifdef HAVE_STRING_H
	strncpy (dest, src, len);
#else
	for ( i = 0; i < len; i++ )
	{
		if ( src[i] == '\0' )
		{
			break;
		}
		dest[i] = src[i];
	}
#endif
	dest[len] = '\0';
}

/* =============================================================== */

#ifndef HAVE_STRDUP
char * __lnb_duplicate_string (
# ifdef LNB_ANSIC
	const char src[])
# else
	src)
	const char src[];
# endif
{
	size_t len;
	char * dest;

	if ( src == NULL )
	{
		return NULL;
	}
	len = strlen (src);
	if ( len == 0 )
	{
		return NULL;
	}
	dest = (char *) malloc (len + 1);
	if ( dest == NULL )
	{
		return NULL;
	}
# ifdef HAVE_STRING_H
	strncpy (dest, src, len);
# else
	LNB_MEMCOPY (dest, src, len);
# endif
	dest[len] = '\0';
	return dest;
}
#endif /* ! HAVE_STRDUP */

/* =============================================================== */

#ifndef HAVE_MEMCPY
void __lnb_memcopy (
# ifdef LNB_ANSIC
	void * const dest, const void * const src, const size_t len)
# else
	dest, src, len)
	void * const dest;
	const void * const src;
	const size_t len;
# endif
{
	size_t i;
	char * const d = (char *)dest;
	const char * const s = (const char *)src;

	for ( i = 0; i < len; i++ )
	{
		d[i] = s[i];
	}
}
#endif /* ! HAVE_MEMCPY */

/* =============================================================== */

#ifndef HAVE_MEMSET
void __lnb_mem_set (
# ifdef LNB_ANSIC
	void * const dest, const char value, const size_t len)
# else
	dest, value, len)
	void * const dest;
	const char value;
	const size_t len;
# endif
{
	size_t i;
	for ( i = 0; i < len; i++ )
	{
		((char *)dest)[i] = value;
	}
}
#endif /* ! HAVE_MEMSET */

/* =============================================================== */

int LNB_ATTR ((constructor))
__lnb_main (LNB_VOID)
{
	if ( __lnb_is_initialized == LNB_INIT_STAGE_NOT_INITIALIZED )
	{
		/* Get pointers to the original functions: */

		*(void **) (&__lnb_real_execve)           = dlsym (RTLD_NEXT, "execve");
		*(void **) (&__lnb_real_fexecve)          = dlsym (RTLD_NEXT, "fexecve");
		*(void **) (&__lnb_real_execveat)         = dlsym (RTLD_NEXT, "execveat");
		*(void **) (&__lnb_real_system)           = dlsym (RTLD_NEXT, "system");
		*(void **) (&__lnb_real_socket)           = dlsym (RTLD_NEXT, "socket");
		*(void **) (&__lnb_real_recvmsg)          = dlsym (RTLD_NEXT, "recvmsg");
		*(void **) (&__lnb_real_sendmsg)          = dlsym (RTLD_NEXT, "sendmsg");
		*(void **) (&__lnb_real_bind)             = dlsym (RTLD_NEXT, "bind");
		*(void **) (&__lnb_real_bindresvport)     = dlsym (RTLD_NEXT, "bindresvport");
		*(void **) (&__lnb_real_bindresvport6)    = dlsym (RTLD_NEXT, "bindresvport6");
		/* file-related functions: */
#ifdef LNB_CANT_USE_VERSIONED_FOPEN
		*(void **) (&__lnb_real_fopen64)          = dlsym  (RTLD_NEXT, "fopen64");
#else
		*(void **) (&__lnb_real_fopen64)          = dlvsym (RTLD_NEXT, "fopen64", "GLIBC_2.1");
		if ( __lnb_real_fopen64 == NULL )
		{
			*(void **) (&__lnb_real_fopen64)  = dlsym (RTLD_NEXT, "fopen64");
		}
#endif
		*(void **) (&__lnb_real_freopen64)        = dlsym  (RTLD_NEXT, "freopen64");
		*(void **) (&__lnb_real_open64)           = dlsym  (RTLD_NEXT, "open64");
		*(void **) (&__lnb_real_openat64)         = dlsym  (RTLD_NEXT, "openat64");

#ifdef LNB_CANT_USE_VERSIONED_FOPEN
		*(void **) (&__lnb_real_fopen)            = dlsym  (RTLD_NEXT, "fopen");
#else
		*(void **) (&__lnb_real_fopen)            = dlvsym (RTLD_NEXT, "fopen", "GLIBC_2.1");
		if ( __lnb_real_fopen == NULL )
		{
			*(void **) (&__lnb_real_fopen)    = dlsym  (RTLD_NEXT, "fopen");
		}
#endif
		*(void **) (&__lnb_real_freopen)          = dlsym  (RTLD_NEXT, "freopen");
		*(void **) (&__lnb_real_open)             = dlsym  (RTLD_NEXT, "open");
		*(void **) (&__lnb_real_openat)           = dlsym  (RTLD_NEXT, "openat");

		/* libpcap functions: */
		*(void **) (&__lnb_real_pcap_create)      = dlsym  (RTLD_NEXT, "pcap_create");
		*(void **) (&__lnb_real_pcap_open_live)   = dlsym  (RTLD_NEXT, "pcap_open_live");

		__lnb_is_initialized = LNB_INIT_STAGE_FULLY_INITIALIZED;

	}	/* is_initialized == 0 */
	return 0;
}

/* =============================================================== */

int
__lnb_get_init_stage (LNB_VOID)
{
	return __lnb_is_initialized;
}

/* =============================================================== */

i_cp_cpp_cpp __lnb_real_execve_location (LNB_VOID)
{
	return __lnb_real_execve;
}

/* =============================================================== */

i_i_cpp_cpp __lnb_real_fexecve_location (LNB_VOID)
{
	return __lnb_real_fexecve;
}

/* =============================================================== */

i_i_cp_cpp_cpp_i __lnb_real_execveat_location (LNB_VOID)
{
	return __lnb_real_execveat;
}

/* =============================================================== */

i_cp __lnb_real_system_location (LNB_VOID)
{
	return __lnb_real_system;
}

/* =============================================================== */

i_i_i_i __lnb_real_socket_location (LNB_VOID)
{
	return __lnb_real_socket;
}

/* =============================================================== */

ss_i_smp_i __lnb_real_recvmsg_location (LNB_VOID)
{
	return __lnb_real_recvmsg;
}

/* =============================================================== */

ss_i_csmp_i __lnb_real_sendmsg_location (LNB_VOID)
{
	return __lnb_real_sendmsg;
}

/* =============================================================== */

fp_cp_cp __lnb_real_fopen64_location (LNB_VOID)
{
	return __lnb_real_fopen64;
}

/* =============================================================== */

fp_cp_cp_fp __lnb_real_freopen64_location (LNB_VOID)
{
	return __lnb_real_freopen64;
}

/* =============================================================== */

i_cp_i_ __lnb_real_open64_location (LNB_VOID)
{
	return __lnb_real_open64;
}

/* =============================================================== */

i_i_cp_i_ __lnb_real_openat64_location (LNB_VOID)
{
	return __lnb_real_openat64;
}

/* =============================================================== */

fp_cp_cp __lnb_real_fopen_location (LNB_VOID)
{
	return __lnb_real_fopen;
}

/* =============================================================== */

fp_cp_cp_fp __lnb_real_freopen_location (LNB_VOID)
{
	return __lnb_real_freopen;
}

/* =============================================================== */

i_cp_i_ __lnb_real_open_location (LNB_VOID)
{
	return __lnb_real_open;
}

/* =============================================================== */

i_i_cp_i_ __lnb_real_openat_location (LNB_VOID)
{
	return __lnb_real_openat;
}

/* =============================================================== */

i_cssp_sl __lnb_real_bind_location (LNB_VOID)
{
	return __lnb_real_bind;
}

/* =============================================================== */

i_i_ssa __lnb_real_bindresvport_loc (LNB_VOID)
{
	return __lnb_real_bindresvport;
}

/* =============================================================== */

i_i_ssa6 __lnb_real_bindresvport6_loc (LNB_VOID)
{
	return __lnb_real_bindresvport6;
}

/* =============================================================== */

pp_ccp_cp __lnb_real_pcap_create_location (LNB_VOID)
{
	return __lnb_real_pcap_create;
}

/* =============================================================== */

pp_ccp_i_i_i_cp __lnb_real_pcap_open_live_loc (LNB_VOID)
{
	return __lnb_real_pcap_open_live;
}
