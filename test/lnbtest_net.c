/*
 * A library library which blocks programs from accessing the network.
 *	-- unit test for network-related functions.
 *
 * Copyright (C) 2015-2021 Bogdan Drozdowski, bogdro (at) users . sourceforge . net
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

#define _POSIX_C_SOURCE 200112L
#define _XOPEN_SOURCE 600
#define _LARGEFILE64_SOURCE 1
#define _BSD_SOURCE 1
#define _SVID_SOURCE 1
#define _DEFAULT_SOURCE 1

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include "libnetblock.h"
#include <check.h>
#include "lnbtest_common.h"

#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif

#ifdef HAVE_ERRNO_H
# include <errno.h>
#else
static int errno = -1;
#endif

#ifdef HAVE_UNISTD_H
# include <unistd.h>
#endif

#include <stdio.h>

#ifdef HAVE_NETDB_H
# include <netdb.h>
#else
struct hostent
{
	char  *h_name;            /* official name of host */
	char **h_aliases;         /* alias list */
	int    h_addrtype;        /* host address type */
	int    h_length;          /* length of address */
	char **h_addr_list;       /* list of addresses */
};
#endif

#ifdef HAVE_SYS_SOCKET_H
# include <sys/socket.h>
#else
# define	PF_NETLINK	16
# define	PF_ROUTE	PF_NETLINK /* Alias to emulate 4.4BSD.  */
# define	AF_NETLINK	PF_NETLINK
# define	AF_ROUTE	PF_ROUTE
struct iovec
{
	void *iov_base;	/* Pointer to data.  */
	size_t iov_len;	/* Length of data.  */
};

struct msghdr
{
	void         *msg_name;       /* optional address */
	socklen_t     msg_namelen;    /* size of address */
	struct iovec *msg_iov;        /* scatter/gather array */
	size_t        msg_iovlen;     /* # elements in msg_iov */
	void         *msg_control;    /* ancillary data, see below */
	socklen_t     msg_controllen; /* ancillary data buffer len */
	int           msg_flags;      /* flags on received message */
};
#endif

#ifdef HAVE_IFADDRS_H
# include <ifaddrs.h>
#endif

#ifdef HAVE_NET_IF_H
# include <net/if.h>
#else
# define IFF_BROADCAST 0x2
#endif

#ifdef HAVE_NETINET_IN_H
# include <netinet/in.h>
#endif

#ifdef HAVE_SYS_UN_H
# include <sys/un.h>
#endif

#ifdef HAVE_ARPA_NAMESER_H
# include <arpa/nameser.h>
#endif

#ifdef HAVE_RESOLV_H
# include <resolv.h>
#endif

#ifdef HAVE_ARPA_INET_H
# include <arpa/inet.h>
#endif

#ifdef HAVE_SYS_SOCKET_H
static in_addr_t addr;
static struct sockaddr_in sa_in;
#endif

/* ====================== Network functions */

#ifdef HAVE_SYS_SOCKET_H
START_TEST(test_socket_unix)
{
	int a;

	LNB_PROLOG_FOR_TEST();
	a = socket (AF_UNIX, SOCK_STREAM, 0);
	if ( a >= 0 )
	{
		close (a);
	}
	else
	{
		fail("test_socket_unix: socket not opened, but should have been: errno=%d\n", errno);
	}
}
END_TEST

START_TEST(test_socket_local)
{
	int a;

	LNB_PROLOG_FOR_TEST();
	a = socket (AF_LOCAL, SOCK_STREAM, 0);
	if ( a >= 0 )
	{
		close (a);
	}
	else
	{
		fail("test_socket_local: socket not opened, but should have been: errno=%d\n", errno);
	}
}
END_TEST

START_TEST(test_socket_banned_netlink)
{
	int a;

	LNB_PROLOG_FOR_TEST();
	a = socket (AF_NETLINK, SOCK_STREAM, PF_INET);
	if ( a >= 0 )
	{
		close (a);
		fail("test_socket_banned_netlink: socket opened, but shouldn't have been\n");
	}
# ifdef HAVE_ERRNO_H
	ck_assert_int_eq(errno, EPERM);
# endif
}
END_TEST

START_TEST(test_socket_banned_raw)
{
	int a;

	LNB_PROLOG_FOR_TEST();
	a = socket (AF_INET, SOCK_RAW, PF_INET);
	if ( a >= 0 )
	{
		close (a);
		fail("test_socket_banned_raw: socket opened, but shouldn't have been\n");
	}
# ifdef HAVE_ERRNO_H
	ck_assert_int_eq(errno, EPERM);
# endif
}
END_TEST

START_TEST(test_socket_banned_raw6)
{
	int a;

	LNB_PROLOG_FOR_TEST();
	a = socket (AF_INET6, SOCK_RAW, PF_INET);
	if ( a >= 0 )
	{
		close (a);
		fail("test_socket_banned_raw6: socket opened, but shouldn't have been\n");
	}
# ifdef HAVE_ERRNO_H
	ck_assert_int_eq(errno, EPERM);
# endif
}
END_TEST

START_TEST(test_socket_banned_proto_netlink)
{
	int a;

	LNB_PROLOG_FOR_TEST();
	a = socket (AF_INET, SOCK_STREAM, PF_NETLINK);
	if ( a >= 0 )
	{
		close (a);
		fail("test_socket_banned_proto_netlink: socket opened, but shouldn't have been\n");
	}
# ifdef HAVE_ERRNO_H
	ck_assert_int_eq(errno, EPERM);
# endif
}
END_TEST

START_TEST(test_socket_banned_proto_netlink6)
{
	int a;

	LNB_PROLOG_FOR_TEST();
	a = socket (AF_INET6, SOCK_STREAM, PF_NETLINK);
	if ( a >= 0 )
	{
		close (a);
		fail("test_socket_banned_proto_netlink6: socket opened, but shouldn't have been\n");
	}
# ifdef HAVE_ERRNO_H
	ck_assert_int_eq(errno, EPERM);
# endif
}
END_TEST

START_TEST(test_socket_banned_inet)
{
	int a;

	LNB_PROLOG_FOR_TEST();
	a = socket (AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if ( a >= 0 )
	{
		close (a);
		fail("test_socket_banned_inet: socket opened, but shouldn't have been\n");
	}
# ifdef HAVE_ERRNO_H
	ck_assert_int_eq(errno, EPERM);
# endif
}
END_TEST

START_TEST(test_socket_banned_inet6)
{
	int a;

	LNB_PROLOG_FOR_TEST();
	a = socket (AF_INET6, SOCK_STREAM, IPPROTO_TCP);
	if ( a >= 0 )
	{
		close (a);
		fail("test_socket_banned_inet6: socket opened, but shouldn't have been\n");
	}
# ifdef HAVE_ERRNO_H
	ck_assert_int_eq(errno, EPERM);
# endif
}
END_TEST

START_TEST(test_socket_banned_proto_inet)
{
	int a;

	LNB_PROLOG_FOR_TEST();
	a = socket (AF_INET, SOCK_STREAM, PF_INET);
	if ( a >= 0 )
	{
		close (a);
		fail("test_socket_banned_proto_inet: socket opened, but shouldn't have been\n");
	}
# ifdef HAVE_ERRNO_H
	ck_assert_int_eq(errno, EPERM);
# endif
}
END_TEST

START_TEST(test_socket_banned_proto_inet6)
{
	int a;

	LNB_PROLOG_FOR_TEST();
	a = socket (AF_INET6, SOCK_STREAM, PF_INET6);
	if ( a >= 0 )
	{
		close (a);
		fail("test_socket_banned_proto_inet6: socket opened, but shouldn't have been\n");
	}
# ifdef HAVE_ERRNO_H
	ck_assert_int_eq(errno, EPERM);
# endif
}
END_TEST

START_TEST(test_recvmsg)
{
	ssize_t a;

	LNB_PROLOG_FOR_TEST();
	a = recvmsg (1, NULL, 0);
	if ( a >= 0 )
	{
		fail("test_recvmsg: data received, but shouldn't have been\n");
	}
# ifdef HAVE_ERRNO_H
	ck_assert_int_eq(errno, EPERM);
# endif
}
END_TEST

START_TEST(test_sendmsg)
{
	ssize_t a;

	LNB_PROLOG_FOR_TEST();
	a = sendmsg (1, NULL, 0);
	if ( a >= 0 )
	{
		fail("test_sendmsg: data sent, but shouldn't have been\n");
	}
# ifdef HAVE_ERRNO_H
	ck_assert_int_eq(errno, EPERM);
# endif
}
END_TEST

# ifdef HAVE_SYS_UN_H
START_TEST(test_bind)
{
	int a;
	int sock;
	int err;
	struct sockaddr_un sa_un;

	LNB_PROLOG_FOR_TEST();
	sock = socket (AF_UNIX, SOCK_STREAM, 0);
	if ( sock >= 0 )
	{
		sa_un.sun_family = AF_UNIX;
		strcpy (sa_un.sun_path, LNB_UNIX_SOCK);
		a = bind (sock, (struct sockaddr*)&sa_un, sizeof (struct sockaddr_un));
		err = errno;
		close (sock);
		unlink (LNB_UNIX_SOCK);
		if ( a < 0 )
		{
			fail("test_bind: socket not bound, but should have been: errno=%d\n", err);
		}
	}
	else
	{
		fail("test_bind: socket not opened, but should have been: errno=%d\n", errno);
	}
}
END_TEST
# endif

START_TEST(test_socketpair)
{
	int twosocks[2];
	int a;

	LNB_PROLOG_FOR_TEST();
	a = socketpair (AF_UNIX, SOCK_STREAM, 0, twosocks);
	if ( a >= 0 )
	{
		close (twosocks[0]);
		close (twosocks[1]);
	}
	else
	{
		fail("test_socket_banned: socketpair not opened, but should have been: errno=%d\n", errno);
	}
}
END_TEST
/*
START_TEST(test_socketpair_banned1)
{
	int twosocks[2];
	int a;

	LNB_PROLOG_FOR_TEST();
	a = socketpair (AF_NETLINK, SOCK_STREAM, PF_INET, twosocks);
	if ( a >= 0 )
	{
		close (twosocks[0]);
		close (twosocks[1]);
		fail("test_socketpair_banned1: socketpair opened, but shouldn't have been\n");
	}
# ifdef HAVE_ERRNO_H
	if (errno != EPERM)
	{
		fail("test_socketpair_banned1: socketpair not opened, but errno not EPERM: errno=%d\n", errno);
	}
# endif
}
END_TEST

START_TEST(test_socketpair_banned2)
{
	int twosocks[2];
	int a;

	LNB_PROLOG_FOR_TEST();
	a = socketpair (AF_INET, SOCK_RAW, PF_INET, twosocks);
	if ( a >= 0 )
	{
		close (twosocks[0]);
		close (twosocks[1]);
		fail("test_socketpair_banned2: socketpair opened, but shouldn't have been\n");
	}
# ifdef HAVE_ERRNO_H
	if (errno != EPERM)
	{
		fail("test_socketpair_banned2: socketpair not opened, but errno not EPERM: errno=%d\n", errno);
	}
# endif
}
END_TEST

START_TEST(test_socketpair_banned3)
{
	int twosocks[2];
	int a;

	LNB_PROLOG_FOR_TEST();
# ifdef SOCK_PACKET
	a = socketpair (AF_INET, SOCK_PACKET, PF_INET, twosocks);
	if ( a >= 0 )
	{
		close (twosocks[0]);
		close (twosocks[1]);
		fail("test_socketpair_banned3: socketpair opened, but shouldn't have been\n");
	}
#  ifdef HAVE_ERRNO_H
	if (errno != EPERM)
	{
		fail("test_socketpair_banned3: socketpair not opened, but errno not EPERM: errno=%d\n", errno);
	}
#  endif
# endif
}
END_TEST
*/
#endif /* HAVE_SYS_SOCKET_H */

/* ========================================================== */

static void setup_net_test(void) /* checked */
{
#ifdef HAVE_SYS_SOCKET_H
	addr = inet_addr ("127.0.0.1");
	sa_in.sin_addr.s_addr = inet_addr ("127.0.0.1");
	sa_in.sin_family = AF_INET;
	sa_in.sin_port = 53;
#endif
}

static void teardown_net_test(void)
{
}

static Suite * lnb_create_suite(void)
{
	Suite * s = suite_create("libnetblock_net");

	TCase * tests_net = tcase_create("net");

/* ====================== Network functions */

#ifdef HAVE_SYS_SOCKET_H
	tcase_add_test(tests_net, test_socket_unix);
	tcase_add_test(tests_net, test_socket_local);
	tcase_add_test(tests_net, test_socket_banned_netlink);
	tcase_add_test(tests_net, test_socket_banned_raw);
	tcase_add_test(tests_net, test_socket_banned_raw6);
	tcase_add_test(tests_net, test_socket_banned_proto_netlink);
	tcase_add_test(tests_net, test_socket_banned_proto_netlink6);
	tcase_add_test(tests_net, test_socket_banned_inet);
	tcase_add_test(tests_net, test_socket_banned_inet6);
	tcase_add_test(tests_net, test_socket_banned_proto_inet);
	tcase_add_test(tests_net, test_socket_banned_proto_inet6);
	tcase_add_test(tests_net, test_recvmsg);
	tcase_add_test(tests_net, test_sendmsg);
# ifdef HAVE_SYS_UN_H
	tcase_add_test(tests_net, test_bind);
# endif
	tcase_add_test(tests_net, test_socketpair);
/*
	tcase_add_test(tests_net, test_socketpair_banned1);
	tcase_add_test(tests_net, test_socketpair_banned2);
	tcase_add_test(tests_net, test_socketpair_banned3);
*/
#endif

/* ====================== */

	tcase_add_checked_fixture(tests_net, &setup_net_test, &teardown_net_test);

	/* set 30-second timeouts */
	tcase_set_timeout(tests_net, 30);

	suite_add_tcase(s, tests_net);

	return s;
}

int main(void)
{
	int failed = 0;

	Suite * s = lnb_create_suite();
	SRunner * sr = srunner_create(s);

	srunner_run_all(sr, CK_NORMAL);

	failed = srunner_ntests_failed(sr);
	srunner_free(sr);

	return failed;
}
