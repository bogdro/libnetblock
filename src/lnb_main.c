/*
 * A library library which blocks programs from accessing the network.
 *
 * Copyright (C) 2011-2012 Bogdan Drozdowski, bogdandr (at) op.pl
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
 * along with this program; if not, write to the Free Software Foudation:
 *		Free Software Foundation
 *		51 Franklin Street, Fifth Floor
 *		Boston, MA 02110-1301
 *		USA
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

#include "lnb_priv.h"

static int	__lnb_is_initialized		= LNB_INIT_STAGE_NOT_INITIALIZED;

/* --- Pointers to original functions. */
/* network-related functions: */
static i_cp_cpp_cpp			__lnb_real_execve		= NULL;
static i_cp				__lnb_real_system		= NULL;
static i_i_i_i				__lnb_real_socket		= NULL;
static ss_i_smp_i			__lnb_real_recvmsg		= NULL;
static ss_i_csmp_i			__lnb_real_sendmsg		= NULL;
static i_cssp_sl			__lnb_real_bind			= NULL;

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

/* =============================================================== */

int LNB_ATTR ((constructor))
__lnb_main (
#ifdef LNB_ANSIC
	void
#endif
)
{
	if ( __lnb_is_initialized == LNB_INIT_STAGE_NOT_INITIALIZED )
	{
		/* Get pointers to the original functions: */

		*(void **) (&__lnb_real_execve)           = dlsym (RTLD_NEXT, "execve");
		*(void **) (&__lnb_real_system)           = dlsym (RTLD_NEXT, "system");
		*(void **) (&__lnb_real_socket)           = dlsym (RTLD_NEXT, "socket");
		*(void **) (&__lnb_real_recvmsg)          = dlsym (RTLD_NEXT, "recvmsg");
		*(void **) (&__lnb_real_sendmsg)          = dlsym (RTLD_NEXT, "sendmsg");
		*(void **) (&__lnb_real_bind)             = dlsym (RTLD_NEXT, "bind");
		/* file-related functions: */
#if (defined HAVE_DLSYM || defined HAVE_LIBDL_DLSYM)			\
	&& (!defined HAVE_DLVSYM) && (!defined HAVE_LIBDL_DLVSYM)	\
	|| ( defined __GLIBC__ && (__GLIBC__ < 2 || (__GLIBC__ == 2 && __GLIBC_MINOR__ < 1) ) )
		*(void **) (&__lnb_real_fopen64)          = dlsym  (RTLD_NEXT, "fopen64");
#else
		*(void **) (&__lnb_real_fopen64)          = dlvsym (RTLD_NEXT, "fopen64", "GLIBC_2.1");
#endif
		*(void **) (&__lnb_real_freopen64)        = dlsym  (RTLD_NEXT, "freopen64");
		*(void **) (&__lnb_real_open64)           = dlsym  (RTLD_NEXT, "open64");
		*(void **) (&__lnb_real_openat64)         = dlsym  (RTLD_NEXT, "openat64");

#if (defined HAVE_DLSYM || defined HAVE_LIBDL_DLSYM)			\
	&& (!defined HAVE_DLVSYM) && (!defined HAVE_LIBDL_DLVSYM)	\
	|| ( defined __GLIBC__ && (__GLIBC__ < 2 || (__GLIBC__ == 2 && __GLIBC_MINOR__ < 1) ) )
		*(void **) (&__lnb_real_fopen)            = dlsym  (RTLD_NEXT, "fopen");
#else
		*(void **) (&__lnb_real_fopen)            = dlvsym (RTLD_NEXT, "fopen", "GLIBC_2.1");
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
__lnb_get_init_stage (
#ifdef LNB_ANSIC
	void
#endif
)
{
	return __lnb_is_initialized;
}

/* =============================================================== */

i_cp_cpp_cpp __lnb_real_execve_location (
#ifdef LNB_ANSIC
	void
#endif
)
{
	return __lnb_real_execve;
}

/* =============================================================== */

i_cp __lnb_real_system_location (
#ifdef LNB_ANSIC
	void
#endif
)
{
	return __lnb_real_system;
}

/* =============================================================== */

i_i_i_i __lnb_real_socket_location (
#ifdef LNB_ANSIC
	void
#endif
)
{
	return __lnb_real_socket;
}

/* =============================================================== */

ss_i_smp_i __lnb_real_recvmsg_location (
#ifdef LNB_ANSIC
	void
#endif
)
{
	return __lnb_real_recvmsg;
}

/* =============================================================== */

ss_i_csmp_i __lnb_real_sendmsg_location (
#ifdef LNB_ANSIC
	void
#endif
)
{
	return __lnb_real_sendmsg;
}

/* =============================================================== */

fp_cp_cp __lnb_real_fopen64_location (
#ifdef LNB_ANSIC
	void
#endif
)
{
	return __lnb_real_fopen64;
}

/* =============================================================== */

fp_cp_cp_fp __lnb_real_freopen64_location (
#ifdef LNB_ANSIC
	void
#endif
)
{
	return __lnb_real_freopen64;
}

/* =============================================================== */

i_cp_i_ __lnb_real_open64_location (
#ifdef LNB_ANSIC
	void
#endif
)
{
	return __lnb_real_open64;
}

/* =============================================================== */

i_i_cp_i_ __lnb_real_openat64_location (
#ifdef LNB_ANSIC
	void
#endif
)
{
	return __lnb_real_openat64;
}

/* =============================================================== */

fp_cp_cp __lnb_real_fopen_location (
#ifdef LNB_ANSIC
	void
#endif
)
{
	return __lnb_real_fopen;
}

/* =============================================================== */

fp_cp_cp_fp __lnb_real_freopen_location (
#ifdef LNB_ANSIC
	void
#endif
)
{
	return __lnb_real_freopen;
}

/* =============================================================== */

i_cp_i_ __lnb_real_open_location (
#ifdef LNB_ANSIC
	void
#endif
)
{
	return __lnb_real_open;
}

/* =============================================================== */

i_i_cp_i_ __lnb_real_openat_location (
#ifdef LNB_ANSIC
	void
#endif
)
{
	return __lnb_real_openat;
}

/* =============================================================== */

i_cssp_sl __lnb_real_bind_location (
#ifdef LNB_ANSIC
	void
#endif
)
{
	return __lnb_real_bind;
}

/* =============================================================== */

pp_ccp_cp __lnb_real_pcap_create_location (
#ifdef LNB_ANSIC
	void
#endif
)
{
	return __lnb_real_pcap_create;
}

/* =============================================================== */

pp_ccp_i_i_i_cp __lnb_real_pcap_open_live_location (
#ifdef LNB_ANSIC
	void
#endif
)
{
	return __lnb_real_pcap_open_live;
}
