/*
 * LibNetBlock - A library which blocks programs from accessing the network.
 *	-- network functions' replacements.
 *
 * Copyright (C) 2011-2022 Bogdan Drozdowski, bogdro (at) users . sourceforge . net
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
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "lnb_cfg.h"

#define _BSD_SOURCE 1
#define _SVID_SOURCE 1
#define _DEFAULT_SOURCE 1

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

/* rpc.h: bindresvport() on FreeBSD */
#ifdef HAVE_RPC_H
# include <rpc.h>
#endif

#ifdef HAVE_RPC_RPC_H
# include <rpc/rpc.h>
#endif

#include "lnb_priv.h"

static int __lnb_allowed_socket_types[] =
{
	AF_UNIX, AF_LOCAL
};

#ifdef TEST_COMPILE
# ifdef LNB_ANSIC
#  define WAS_LNB_ANSIC
# endif
# undef LNB_ANSIC
#endif

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

/* problem with type portability - skip checking these functions */
#if (defined TEST_COMPILE) && (defined WAS_LNB_ANSIC)
# define LNB_ANSIC 1
#endif

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

#ifdef TEST_COMPILE
# undef LNB_ANSIC
#endif

/* =============================================================== */

#if (defined HAVE_BINDRESVPORT) \
	&& (!defined __sun) /* skip on SunOS - different arguments, subject to changes */

# ifdef TEST_COMPILE
#  undef LNB_ANSIC
# endif

int
bindresvport (
# ifdef LNB_ANSIC
	int sockfd, struct sockaddr_in *my_addr)
# else
	sockfd, my_addr)
	int sockfd;
	struct sockaddr_in *my_addr;
# endif
{
	LNB_MAKE_ERRNO_VAR(err);

	__lnb_main ();
# ifdef LNB_DEBUG
	fprintf (stderr, "libnetblock: bindresvport()\n");
	fflush (stderr);
# endif

	if ( __lnb_real_bindresvport_location () == NULL )
	{
		LNB_SET_ERRNO_MISSING();
		return -1;
	}

	if ( my_addr == NULL )
	{
		LNB_SET_ERRNO (err);
		return (*__lnb_real_bindresvport_location ()) (sockfd, my_addr);
	}

	if ( (__lnb_check_prog_ban () != 0)
		|| (__lnb_get_init_stage() != LNB_INIT_STAGE_FULLY_INITIALIZED) )
	{
		LNB_SET_ERRNO (err);
		return (*__lnb_real_bindresvport_location ()) (sockfd, my_addr);
	}

	if ( __lnb_is_allowed_socket (my_addr->sin_family) == 1 )
	{
		LNB_SET_ERRNO(err);
		return (*__lnb_real_bindresvport_location ()) (sockfd, my_addr);
	}

	LNB_SET_ERRNO_PERM();
	return -1;
}
#endif /* (defined HAVE_BINDRESVPORT) && (!defined __sun) */

/* =============================================================== */

#if (defined HAVE_BINDRESVPORT6) \
	&& (!defined __sun) /* skip on SunOS, just like bindresvport() */

int
bindresvport6 (
# ifdef LNB_ANSIC
	int sockfd, struct sockaddr_in6 *my_addr)
# else
	sockfd, my_addr)
	int sockfd;
	struct sockaddr_in6 *my_addr;
# endif
{
	LNB_MAKE_ERRNO_VAR(err);

	__lnb_main ();
# ifdef LNB_DEBUG
	fprintf (stderr, "libnetblock: bindresvport6()\n");
	fflush (stderr);
# endif

	if ( __lnb_real_bindresvport6_location () == NULL )
	{
		LNB_SET_ERRNO_MISSING();
		return -1;
	}

	if ( my_addr == NULL )
	{
		LNB_SET_ERRNO (err);
		return (*__lnb_real_bindresvport6_location ()) (sockfd, my_addr);
	}

	if ( (__lnb_check_prog_ban () != 0)
		|| (__lnb_get_init_stage() != LNB_INIT_STAGE_FULLY_INITIALIZED) )
	{
		LNB_SET_ERRNO (err);
		return (*__lnb_real_bindresvport6_location ()) (sockfd, my_addr);
	}

	if ( __lnb_is_allowed_socket (my_addr->sin6_family) == 1 )
	{
		LNB_SET_ERRNO(err);
		return (*__lnb_real_bindresvport6_location ()) (sockfd, my_addr);
	}

	LNB_SET_ERRNO_PERM();
	return -1;
}
#endif /* (defined HAVE_BINDRESVPORT6) && (!defined __sun) */
