/*
 * A library library which blocks programs from accessing the network.
 *	-- libpcap functions' replacements.
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

#include "lnb_cfg.h"

#include "lnb_priv.h"

#include <stddef.h> /* NULL */
#include <stdio.h> /* FILE */

#ifdef HAVE_INTTYPES_H
# include <inttypes.h>	/* intptr_t */
#endif

#ifdef HAVE_STDINT_H
# include <stdint.h>	/* intptr_t */
#endif

#ifdef HAVE_PCAP_H
# include <pcap.h>
#else
# ifdef HAVE_PCAP_PCAP_H
#  include <pcap/pcap.h>
# else
/* already included in lnb_priv.h: */
/*
typedef void pcap_t;
typedef void pcap_if_t;
typedef unsigned int bpf_u_int32;
typedef unsigned int intptr_t;
*/
char * pcap_lookupdev PARAMS ((char *errbuf));
int pcap_lookupnet PARAMS ((const char * device, bpf_u_int32 * netp,
	bpf_u_int32 * maskp, char * errbuf));
pcap_t * pcap_create PARAMS ((const char * source, char * errbuf));
pcap_t * pcap_open_dead PARAMS ((int linktype, int snaplen));
pcap_t * pcap_open_live PARAMS ((const char * device, int snaplen,
	int promisc, int to_ms, char * errbuf));
pcap_t * pcap_open_offline PARAMS ((const char * fname, char * errbuf));
pcap_t * pcap_fopen_offline PARAMS ((FILE * fp, char * errbuf));
int pcap_findalldevs PARAMS ((pcap_if_t ** devs, char * errbuf));
# endif
#endif
#if ! defined(WIN32)
pcap_t * pcap_hopen_offline PARAMS ((intptr_t a, char * errbuf));
#endif

/* =============================================================== */

pcap_t *
pcap_create (
#ifdef LNB_ANSIC
	const char * source, char * errbuf)
#else
	source, errbuf)
	const char * source;
	char * errbuf;
#endif
{
	__lnb_main ();

#ifdef LNB_DEBUG
	fprintf (stderr, "libnetblock: pcap_create(%s)\n", (source==NULL)? "null" : source);
	fflush (stderr);
#endif

	if ( __lnb_real_pcap_create_location () == NULL )
	{
		return NULL;
	}

	if ( (__lnb_check_prog_ban () != 0) || (__lnb_get_init_stage () < 2) )
	{
		return (*__lnb_real_pcap_create_location ()) (source, errbuf);
	}

	return NULL;
}

/* =============================================================== */

pcap_t *
pcap_open_live (
#ifdef LNB_ANSIC
	const char * device, int snaplen,
	int promisc, int to_ms, char * errbuf)
#else
	device, snaplen, promisc, to_ms, errbuf)
	const char * device;
	int snaplen;
	int promisc;
	int to_ms;
	char * errbuf;
#endif
{
	__lnb_main ();

#ifdef LNB_DEBUG
	fprintf (stderr, "libnetblock: pcap_open_live(%s)\n", (device==NULL)? "null" : device);
	fflush (stderr);
#endif

	if ( __lnb_real_pcap_open_live_location () == NULL )
	{
		return NULL;
	}

	if ( (__lnb_check_prog_ban () != 0) || (__lnb_get_init_stage () < 2) )
	{
		return (*__lnb_real_pcap_open_live_location ()) (device, snaplen, promisc, to_ms, errbuf);
	}

	return NULL;
}

