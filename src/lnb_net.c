/*
 * A library library which blocks programs from accessing the network.
 *	-- network functions' replacements.
 *
 * Copyright (C) 2011-2017 Bogdan Drozdowski, bogdandr (at) op.pl
 * Parts of this file are Copyright (C) Free Software Foundation, Inc.
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

#define _BSD_SOURCE 1
#define _SVID_SOURCE 1

#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif

#include <stdio.h>

#ifdef HAVE_ERRNO_H
# include <errno.h>
#endif

#ifdef HAVE_STDLIB_H
# include <stdlib.h>		/* sys/socket.h */
#endif

#ifdef HAVE_NETINET_IN_H
# include <netinet/in.h>
#endif

#ifdef HAVE_SYS_SOCKET_H
# include <sys/socket.h>
#endif

#include "lnb_priv.h"

static int __lnb_allowed_socket_types[] =
{
	AF_UNIX, AF_LOCAL
};

/* =============================================================== */

#ifndef LNB_ANSIC
static int __lnb_is_allowed_socket LNB_PARAMS ((const int socket_type));
#endif

/**
 * Tells if the given socket type is forbidden to use.
 * \param socket_type The socket type to check.
 * \return 1 if forbidden, 0 otherwise.
 */
static int __lnb_is_allowed_socket (
#ifdef LNB_ANSIC
	const int socket_type)
#else
	socket_type)
	const int socket_type;
#endif
{
	size_t i;
	for ( i = 0;
		i < sizeof (__lnb_allowed_socket_types) / sizeof (__lnb_allowed_socket_types[0]);
		i++ )
	{
		if ( __lnb_allowed_socket_types[i] == socket_type )
		{
			return 1;
		}
	}
	return 0;
}

/* =============================================================== */

int
socket (
#ifdef LNB_ANSIC
	int domain, int type, int protocol)
#else
	domain, type, protocol)
	int domain;
	int type;
	int protocol;
#endif
{
	LNB_MAKE_ERRNO_VAR(err);

	__lnb_main ();
#ifdef LNB_DEBUG
	fprintf (stderr, "libnetblock: socket(%d, %d, %d)\n", domain, type, protocol);
	fflush (stderr);
#endif

	if ( __lnb_real_socket_location () == NULL )
	{
		LNB_SET_ERRNO_MISSING();
		return -1;
	}

	if ( (__lnb_check_prog_ban () != 0)
		|| (__lnb_get_init_stage () < LNB_INIT_STAGE_FULLY_INITIALIZED) )
	{
		LNB_SET_ERRNO(err);
		return (*__lnb_real_socket_location ()) (domain, type, protocol);
	}

	if ( __lnb_is_allowed_socket (domain) == 1 )
	{
		LNB_SET_ERRNO(err);
		return (*__lnb_real_socket_location ()) (domain, type, protocol);
	}

	LNB_SET_ERRNO_PERM();
	return -1;
}

/* =============================================================== */

ssize_t
recvmsg (
#ifdef LNB_ANSIC
	int s, struct msghdr *msg, int flags)
#else
	s, msg, flags)
	int s;
	struct msghdr *msg;
	int flags;
#endif
{
	LNB_MAKE_ERRNO_VAR(err);

	__lnb_main ();
#ifdef LNB_DEBUG
	fprintf (stderr, "libnetblock: recvmsg(%d)\n", s);
	fflush (stderr);
#endif

	if ( __lnb_real_recvmsg_location () == NULL )
	{
		LNB_SET_ERRNO_MISSING();
		return -1;
	}

	if ( (__lnb_check_prog_ban () != 0)
		|| (__lnb_get_init_stage () < LNB_INIT_STAGE_FULLY_INITIALIZED) )
	{
		LNB_SET_ERRNO(err);
		return (*__lnb_real_recvmsg_location ()) (s, msg, flags);
	}

	LNB_SET_ERRNO_PERM();
	return -1;
}

/* =============================================================== */

ssize_t
sendmsg (
#ifdef LNB_ANSIC
	int s, const struct msghdr *msg, int flags)
#else
	s, msg, flags)
	int s;
	const struct msghdr *msg;
	int flags;
#endif
{
	LNB_MAKE_ERRNO_VAR(err);

	__lnb_main ();
#ifdef LNB_DEBUG
	fprintf (stderr, "libnetblock: sendmsg(%d)\n", s);
	fflush (stderr);
#endif

	if ( __lnb_real_sendmsg_location () == NULL )
	{
		LNB_SET_ERRNO_MISSING();
		return -1;
	}

	if ( (__lnb_check_prog_ban () != 0)
		|| (__lnb_get_init_stage () < LNB_INIT_STAGE_FULLY_INITIALIZED) )
	{
		LNB_SET_ERRNO(err);
		return (*__lnb_real_sendmsg_location ()) (s, msg, flags);
	}

	LNB_SET_ERRNO_PERM();
	return -1;
}

/* =============================================================== */

int
bind (
#ifdef LNB_ANSIC
	int sockfd, const struct sockaddr *my_addr, socklen_t addrlen)
#else
	sockfd, my_addr, addrlen)
	int sockfd;
	const struct sockaddr *my_addr;
	socklen_t addrlen;
#endif
{
	LNB_MAKE_ERRNO_VAR(err);

	__lnb_main ();
#ifdef LNB_DEBUG
	fprintf (stderr, "libnetblock: bind()\n");
	fflush (stderr);
#endif

	if ( __lnb_real_bind_location () == NULL )
	{
		LNB_SET_ERRNO_MISSING();
		return -1;
	}

	if ( my_addr == NULL )
	{
		LNB_SET_ERRNO(err);
		return (*__lnb_real_bind_location ()) (sockfd, my_addr, addrlen);
	}

	if ( (__lnb_check_prog_ban () != 0)
		|| (__lnb_get_init_stage () < LNB_INIT_STAGE_FULLY_INITIALIZED) )
	{
		LNB_SET_ERRNO(err);
		return (*__lnb_real_bind_location ()) (sockfd, my_addr, addrlen);
	}

	if ( __lnb_is_allowed_socket (my_addr->sa_family) == 1 )
	{
		LNB_SET_ERRNO(err);
		return (*__lnb_real_bind_location ()) (sockfd, my_addr, addrlen);
	}

	LNB_SET_ERRNO_PERM();
	return -1;
}
