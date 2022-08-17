/*
 * A library library which blocks programs from accessing the network.
 *	-- unit test.
 *
 * Copyright (C) 2015 Bogdan Drozdowski, bogdandr (at) op.pl
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

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

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
# ifdef LSR_ANSIC
#  error Dynamic loading functions missing.
# endif
#endif

#include <libnetblock.h>
#include <check.h>

/* compatibility with older check versions */
#ifndef ck_abort
# define ck_abort() ck_abort_msg(NULL)
# define ck_abort_msg fail
# define ck_assert(C) ck_assert_msg(C, NULL)
# define ck_assert_msg fail_unless
#endif

#ifndef _ck_assert_int
# define _ck_assert_int(X, O, Y) ck_assert_msg((X) O (Y), "Assertion '"#X#O#Y"' failed: "#X"==%d, "#Y"==%d", X, Y)
# define ck_assert_int_eq(X, Y) _ck_assert_int(X, ==, Y)
# define ck_assert_int_ne(X, Y) _ck_assert_int(X, !=, Y)
#endif

#ifndef _ck_assert_str
# define _ck_assert_str(C, X, O, Y) ck_assert_msg(C, "Assertion '"#X#O#Y"' failed: "#X"==\"%s\", "#Y"==\"%s\"", X, Y)
# define ck_assert_str_eq(X, Y) _ck_assert_str(!strcmp(X, Y), X, ==, Y)
# define ck_assert_str_ne(X, Y) _ck_assert_str(strcmp(X, Y), X, !=, Y)
#endif

#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif

#ifdef HAVE_ERRNO_H
# include <errno.h>
#else
static int errno = -1;
#endif

#ifdef HAVE_MALLOC_H
# include <malloc.h>
#endif

#ifdef HAVE_UNISTD_H
# include <unistd.h>
#endif

#include <stdio.h>

#ifdef HAVE_STDLIB_H
# include <stdlib.h>
#endif

#ifdef HAVE_STRING_H
# if (!defined STDC_HEADERS) && (defined HAVE_MEMORY_H)
#  include <memory.h>
# endif
# include <string.h>
#endif

#ifdef HAVE_FCNTL_H
# include <fcntl.h>
#else
# define O_RDONLY	0
# define O_WRONLY	1
# define O_RDWR		2
# define O_TRUNC	01000
#endif

#ifdef HAVE_SYS_STAT_H
# include <sys/stat.h>
#else
# define S_IRUSR 0600
# define S_IWUSR 0400
#endif

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

#ifdef HAVE_PCAP_H
# include <pcap.h>
#else
# ifdef HAVE_PCAP_PCAP_H
#  include <pcap/pcap.h>
# endif
#endif

#ifdef HAVE_SYS_UTSNAME_H
# include <sys/utsname.h>
#endif

#ifdef HAVE_ARPA_INET_H
# include <arpa/inet.h>
#endif

#ifdef HAVE_SYS_IOCTL_H
# include <sys/ioctl.h>
#endif

/* ====================== File functions */

#define LNB_TEST_FILENAME "zz1"
#define LNB_TEST_FILE_LENGTH 3
#define LNB_LINK_FILENAME "zz1link"
#define LNB_TEST_BANNED_FILENAME "/etc/hosts"
#define LNB_TEST_BANNED_FILENAME_SHORT "hosts"
#define LNB_TEST_BANNED_LINKNAME "banlink"
#define LNB_UNIX_SOCK "stest.sock"

#ifdef HAVE_SYS_SOCKET_H
static in_addr_t addr;
static struct sockaddr_in sa_in;
#endif

#ifdef HAVE_OPENAT
START_TEST(test_openat)
{
	int fd;

	printf("test_openat\n");
	fd = openat(AT_FDCWD, LNB_TEST_FILENAME, O_RDONLY);
	if (fd >= 0)
	{
		close(fd);
	}
	else
	{
		fail("test_openat: file not opened: errno=%d\n", errno);
	}
}
END_TEST

START_TEST(test_openat_banned)
{
	int fd;
	int dirfd;

	printf("test_openat_banned\n");
	fd = openat(AT_FDCWD, LNB_TEST_BANNED_FILENAME, O_RDONLY);
	if (fd >= 0)
	{
		close(fd);
		fail("test_openat_banned: file opened, but shouldn't be (1)\n");
	}
# ifdef HAVE_ERRNO_H
	ck_assert_int_eq(errno, EPERM);
# endif
	dirfd = open("/etc", O_RDONLY);
	if (dirfd >= 0)
	{
		fd = openat(dirfd, LNB_TEST_BANNED_FILENAME_SHORT, O_RDONLY);
		if (fd >= 0)
		{
			close(fd);
			close(dirfd);
			fail("test_openat_banned: file opened, but shouldn't be (2)\n");
		}
		close(dirfd);
# ifdef HAVE_ERRNO_H
		if (errno != EPERM)
		{
			fail("test_openat_banned: file not opened, but errno invalid: errno=%d\n", errno);
		}
# endif
	}
	else
	{
		fail("test_openat_banned: dir not opened, but should be: errno=%d\n", errno);
	}
}
END_TEST

# ifdef HAVE_SYMLINK
START_TEST(test_openat_link)
{
	int fd;
	int r;

	printf("test_openat_link\n");
	r = symlink (LNB_TEST_FILENAME, LNB_LINK_FILENAME);
	if (r != 0)
	{
		fail("test_openat_link: link could not be created: errno=%d, r=%d\n", errno, r);
	}
	fd = openat(AT_FDCWD, LNB_LINK_FILENAME, O_RDONLY);
	if (fd >= 0)
	{
		close(fd);
		r = unlink (LNB_LINK_FILENAME);
		if (r != 0)
		{
			fail("test_openat_link: link could not be deleted: errno=%d, r=%d\n", errno, r);
		}
	}
	else
	{
		unlink (LNB_LINK_FILENAME);
		fail("test_openat_link: file not opened: errno=%d\n", errno);
	}
}
END_TEST

START_TEST(test_openat_link_banned)
{
	int fd;
	int r;

	printf("test_openat_link_banned\n");
	r = symlink (LNB_TEST_BANNED_FILENAME, LNB_TEST_BANNED_LINKNAME);
	if (r != 0)
	{
		fail("test_openat_link_banned: link could not be created: errno=%d, r=%d\n", errno, r);
	}
	fd = openat(AT_FDCWD, LNB_TEST_BANNED_LINKNAME, O_RDONLY);
	if (fd >= 0)
	{
		close(fd);
		unlink (LNB_TEST_BANNED_LINKNAME);
		fail("test_openat_link_banned: file opened, but shouldn't be\n");
	}
	r = errno;
	unlink (LNB_TEST_BANNED_LINKNAME);
#  ifdef HAVE_ERRNO_H
	ck_assert_int_eq(r, EPERM);
#  endif
}
END_TEST
# endif /* HAVE_SYMLINK */
#endif /* HAVE_OPENAT */

START_TEST(test_fopen)
{
	FILE * f;

	printf("test_fopen\n");
	f = fopen(LNB_TEST_FILENAME, "r");
	if (f != NULL)
	{
		fclose(f);
	}
	else
	{
		fail("test_fopen: file not opened: errno=%d\n", errno);
	}
}
END_TEST

START_TEST(test_fopen_banned)
{
	FILE * f;

	printf("test_fopen_banned\n");
	f = fopen(LNB_TEST_BANNED_FILENAME, "r");
	if (f != NULL)
	{
		fclose(f);
		fail("test_fopen_banned: file opened, but shouldn't be\n");
	}
#ifdef HAVE_ERRNO_H
	ck_assert_int_eq(errno, EPERM);
#endif
}
END_TEST

#ifdef HAVE_SYMLINK
START_TEST(test_fopen_link)
{
	FILE * f;
	int r;

	printf("test_fopen_link\n");
	r = symlink (LNB_TEST_FILENAME, LNB_LINK_FILENAME);
	if (r != 0)
	{
		fail("test_fopen_link: link could not be created: errno=%d, r=%d\n", errno, r);
	}
	f = fopen(LNB_LINK_FILENAME, "r");
	if (f != NULL)
	{
		unlink (LNB_LINK_FILENAME);
		fclose(f);
	}
	else
	{
		r = errno;
		unlink (LNB_LINK_FILENAME);
		fail("test_fopen_link: file not opened: errno=%d\n", r);
	}
}
END_TEST

START_TEST(test_fopen_link_banned)
{
	FILE * f;
	int r;

	printf("test_fopen_link_banned\n");
	r = symlink (LNB_TEST_BANNED_FILENAME, LNB_TEST_BANNED_LINKNAME);
	if (r != 0)
	{
		fail("test_fopen_link_banned: link could not be created: errno=%d, r=%d\n", errno, r);
	}
	f = fopen(LNB_TEST_BANNED_LINKNAME, "r");
	if (f != NULL)
	{
		unlink (LNB_TEST_BANNED_LINKNAME);
		fclose(f);
		fail("test_fopen_link_banned: file opened, but shouldn't be\n");
	}
	r = errno;
	unlink (LNB_TEST_BANNED_LINKNAME);
# ifdef HAVE_ERRNO_H
	ck_assert_int_eq(errno, EPERM);
# endif
}
END_TEST
#endif /* HAVE_SYMLINK */

START_TEST(test_freopen)
{
	FILE * f;

	printf("test_freopen\n");
	f = fopen(LNB_TEST_FILENAME, "r");
	if (f != NULL)
	{
		f = freopen(LNB_TEST_FILENAME, "r", f);
		if (f != NULL)
		{
			fclose(f);
		}
		else
		{
			fail("test_freopen: file not re-opened: errno=%d\n", errno);
		}
	}
	else
	{
		fail("test_freopen: file not opened: errno=%d\n", errno);
	}
}
END_TEST

START_TEST(test_freopen_banned)
{
	FILE * f;

	printf("test_freopen_banned\n");
	f = fopen(LNB_TEST_FILENAME, "r");
	if (f != NULL)
	{
		f = freopen(LNB_TEST_BANNED_FILENAME, "r", f);
		if (f != NULL)
		{
			fclose(f);
			fail("test_freopen_banned: file opened, but shouldn't be\n");
		}
#ifdef HAVE_ERRNO_H
		ck_assert_int_eq(errno, EPERM);
#endif
	}
	else
	{
		fail("test_freopen_banned: file not opened: errno=%d\n", errno);
	}
}
END_TEST

#ifdef HAVE_SYMLINK
START_TEST(test_freopen_link)
{
	FILE * f;
	int r;

	printf("test_freopen_link\n");
	r = symlink (LNB_TEST_FILENAME, LNB_LINK_FILENAME);
	if (r != 0)
	{
		fail("test_freopen_link: link could not be created: errno=%d, r=%d\n", errno, r);
	}
	f = fopen(LNB_LINK_FILENAME, "r");
	if (f != NULL)
	{
		f = freopen(LNB_LINK_FILENAME, "r", f);
		if (f != NULL)
		{
			fclose(f);
			unlink (LNB_LINK_FILENAME);
		}
		else
		{
			r = errno;
			unlink (LNB_LINK_FILENAME);
			fail("test_freopen_link: file not re-opened: errno=%d\n", r);
		}
	}
	else
	{
		unlink (LNB_LINK_FILENAME);
		fail("test_freopen_link: file not opened: errno=%d\n", errno);
	}
}
END_TEST

START_TEST(test_freopen_link_banned)
{
	FILE * f;
	int r;

	printf("test_freopen_link_banned\n");
	r = symlink (LNB_TEST_BANNED_FILENAME, LNB_TEST_BANNED_LINKNAME);
	if (r != 0)
	{
		fail("test_freopen_link_banned: link could not be created: errno=%d, r=%d\n", errno, r);
	}
	f = fopen(LNB_TEST_FILENAME, "r");
	if (f != NULL)
	{
		f = freopen(LNB_TEST_BANNED_LINKNAME, "r", f);
		if (f != NULL)
		{
			fclose(f);
			unlink (LNB_TEST_BANNED_LINKNAME);
			fail("test_freopen_link_banned: file opened, but shouldn't be\n");
		}
		r = errno;
		unlink (LNB_TEST_BANNED_LINKNAME);
# ifdef HAVE_ERRNO_H
		ck_assert_int_eq(r, EPERM);
# endif
	}
	else
	{
		unlink (LNB_TEST_BANNED_LINKNAME);
		fail("test_freopen_link_banned: file not opened: errno=%d\n", errno);
	}
}
END_TEST
#endif /* HAVE_SYMLINK */

START_TEST(test_open)
{
	int fd;

	printf("test_open\n");
	fd = open(LNB_TEST_FILENAME, O_RDONLY);
	if (fd >= 0)
	{
		close(fd);
	}
	else
	{
		fail("test_open: file not opened: errno=%d\n", errno);
	}
}
END_TEST

START_TEST(test_open_banned)
{
	int fd;

	printf("test_open_banned\n");
	fd = open(LNB_TEST_BANNED_FILENAME, O_RDONLY);
	if (fd >= 0)
	{
		close(fd);
		fail("test_open_banned: file opened, but shouldn't be\n");
	}
#ifdef HAVE_ERRNO_H
	ck_assert_int_eq(errno, EPERM);
#endif
}
END_TEST

#ifdef HAVE_SYMLINK
START_TEST(test_open_link)
{
	int fd;
	int r;

	printf("test_open_link\n");
	r = symlink (LNB_TEST_FILENAME, LNB_LINK_FILENAME);
	if (r != 0)
	{
		fail("test_open_link: link could not be created: errno=%d, r=%d\n", errno, r);
	}
	fd = open(LNB_LINK_FILENAME, O_RDONLY);
	if (fd >= 0)
	{
		close(fd);
		unlink (LNB_LINK_FILENAME);
	}
	else
	{
		r = errno;
		unlink (LNB_LINK_FILENAME);
		fail("test_open_link: file not opened: errno=%d\n", r);
	}
}
END_TEST

START_TEST(test_open_link_banned)
{
	int fd;
	int r;

	printf("test_open_link_banned\n");
	r = symlink (LNB_TEST_BANNED_FILENAME, LNB_TEST_BANNED_LINKNAME);
	if (r != 0)
	{
		fail("test_freopen_link: link could not be created: errno=%d, r=%d\n", errno, r);
	}
	fd = open(LNB_TEST_BANNED_LINKNAME, O_RDONLY);
	if (fd >= 0)
	{
		close(fd);
		unlink (LNB_TEST_BANNED_LINKNAME);
		fail("test_open_link_banned: file opened, but shouldn't be\n");
	}
	r = errno;
	unlink (LNB_TEST_BANNED_LINKNAME);
# ifdef HAVE_ERRNO_H
	ck_assert_int_eq(r, EPERM);
# endif
}
END_TEST
#endif /* HAVE_SYMLINK */

/* ====================== Network functions */

#ifdef HAVE_SYS_SOCKET_H
START_TEST(test_socket1)
{
	int a;

	printf("test_socket1\n");
	a = socket (AF_UNIX, SOCK_STREAM, 0);
	if ( a >= 0 )
	{
		close (a);
	}
	else
	{
		fail("test_socket1: socket not opened, but should be: errno=%d\n", errno);
	}
}
END_TEST

START_TEST(test_socket2)
{
	int a;

	printf("test_socket2\n");
	a = socket (AF_LOCAL, SOCK_STREAM, 0);
	if ( a >= 0 )
	{
		close (a);
	}
	else
	{
		fail("test_socket2: socket not opened, but should be: errno=%d\n", errno);
	}
}
END_TEST

START_TEST(test_socket_banned1)
{
	int a;

	printf("test_socket_banned1\n");
	a = socket (AF_NETLINK, SOCK_STREAM, PF_INET);
	if ( a >= 0 )
	{
		close (a);
		fail("test_socket_banned1: socket opened, but shouldn't be\n");
	}
# ifdef HAVE_ERRNO_H
	ck_assert_int_eq(errno, EPERM);
# endif
}
END_TEST

START_TEST(test_socket_banned2)
{
	int a;

	printf("test_socket_banned2\n");
	a = socket (AF_INET, SOCK_RAW, PF_INET);
	if ( a >= 0 )
	{
		close (a);
		fail("test_socket_banned2: socket opened, but shouldn't be\n");
	}
# ifdef HAVE_ERRNO_H
	ck_assert_int_eq(errno, EPERM);
# endif
}
END_TEST

START_TEST(test_socket_banned3)
{
	int a;

	printf("test_socket_banned3\n");
	a = socket (AF_INET, SOCK_STREAM, PF_NETLINK);
	if ( a >= 0 )
	{
		close (a);
		fail("test_socket_banned3: socket opened, but shouldn't be\n");
	}
# ifdef HAVE_ERRNO_H
	ck_assert_int_eq(errno, EPERM);
# endif
}
END_TEST

START_TEST(test_socket_banned4)
{
	int a;

	printf("test_socket_banned4\n");
	a = socket (AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if ( a >= 0 )
	{
		close (a);
		fail("test_socket_banned4: socket opened, but shouldn't be\n");
	}
# ifdef HAVE_ERRNO_H
	ck_assert_int_eq(errno, EPERM);
# endif
}
END_TEST

START_TEST(test_socket_banned5)
{
	int a;

	printf("test_socket_banned5\n");
	a = socket (AF_INET, SOCK_STREAM, PF_INET);
	if ( a >= 0 )
	{
		close (a);
		fail("test_socket_banned5: socket opened, but shouldn't be\n");
	}
# ifdef HAVE_ERRNO_H
	ck_assert_int_eq(errno, EPERM);
# endif
}
END_TEST

START_TEST(test_recvmsg)
{
	int a;

	printf("test_recvmsg\n");
	a = recvmsg (1, NULL, 0);
	if ( a >= 0 )
	{
		fail("test_recvmsg: data received, but shouldn't be\n");
	}
# ifdef HAVE_ERRNO_H
	ck_assert_int_eq(errno, EPERM);
# endif
}
END_TEST

START_TEST(test_sendmsg)
{
	int a;

	printf("test_sendmsg\n");
	a = sendmsg (1, NULL, 0);
	if ( a >= 0 )
	{
		fail("test_sendmsg: data sent, but shouldn't be\n");
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

	printf("test_bind\n");
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
			fail("test_bind: socket not bound, but should be: errno=%d\n", err);
		}
	}
	else
	{
		fail("test_bind: socket not opened, but should be: errno=%d\n", errno);
	}
}
END_TEST
# endif

START_TEST(test_socketpair)
{
	int twosocks[2];
	int a;

	printf("test_socketpair\n");
	a = socketpair (AF_UNIX, SOCK_STREAM, 0, twosocks);
	if ( a >= 0 )
	{
		close (twosocks[0]);
		close (twosocks[1]);
	}
	else
	{
		fail("test_socket_banned: socketpair not opened, but should be: errno=%d\n", errno);
	}
}
END_TEST
/*
START_TEST(test_socketpair_banned1)
{
	int twosocks[2];
	int a;

	printf("test_socketpair_banned1\n");
	a = socketpair (AF_NETLINK, SOCK_STREAM, PF_INET, twosocks);
	if ( a >= 0 )
	{
		close (twosocks[0]);
		close (twosocks[1]);
		fail("test_socketpair_banned1: socketpair opened, but shouldn't be\n");
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

	printf("test_socketpair_banned2\n");
	a = socketpair (AF_INET, SOCK_RAW, PF_INET, twosocks);
	if ( a >= 0 )
	{
		close (twosocks[0]);
		close (twosocks[1]);
		fail("test_socketpair_banned2: socketpair opened, but shouldn't be\n");
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

	printf("test_socketpair_banned3\n");
# ifdef SOCK_PACKET
	a = socketpair (AF_INET, SOCK_PACKET, PF_INET, twosocks);
	if ( a >= 0 )
	{
		close (twosocks[0]);
		close (twosocks[1]);
		fail("test_socketpair_banned3: socketpair opened, but shouldn't be\n");
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

/* ====================== Execution functions */

#ifdef HAVE_UNISTD_H
START_TEST(test_execve)
{
	int a;
	char progname[] = "/bin/cat";
	char fname[] = LNB_TEST_FILENAME;
	char * args[] = { NULL, NULL, NULL };
	char * envp[] = { NULL };

	printf("test_execve\n");
	args[0] = progname;
	args[1] = fname;
	a = execve (progname, args, envp);
	fail("test_execve: the program didn't run, but it should"); /* should never be reached */
}
END_TEST

START_TEST(test_execve_banned)
{
	int a;
	char * args[] = { NULL };

	printf("test_execve_banned\n");
	a = execve ("/sbin/ifconfig", args, NULL);
	ck_assert_int_ne(a, 0);
}
END_TEST
#endif /* HAVE_UNISTD_H */

START_TEST(test_system)
{
	int a;

	printf("test_system\n");
	a = system ("cat " LNB_TEST_FILENAME);
	ck_assert_int_eq(a, 0);
}
END_TEST

START_TEST(test_system_banned)
{
	int a;

	printf("test_system_banned\n");
	a = system ("/sbin/ifconfig");
	ck_assert_int_ne(a, 0);
}
END_TEST


/* ====================== Packet capture functions */

#if (defined HAVE_PCAP_H) || (defined HAVE_PCAP_PCAP_H)
static char buf[5000];

START_TEST(test_pcap_create)
{
	pcap_t * ret;

	printf("test_pcap_create\n");
	ret = pcap_create ("eth0", buf);
	if (ret != NULL)
	{
		pcap_close(ret);
		fail("test_pcap_create: capture created, but shouldn't have been\n");
	}
}
END_TEST

START_TEST(test_pcap_open_live)
{
	pcap_t * ret;

	printf("test_pcap_open_live\n");
	ret = pcap_open_live ("eth0", 100, 0, 1000, buf);
	if (ret != NULL)
	{
		pcap_close(ret);
		fail("test_pcap_open_live: capture opened, but shouldn't have been\n");
	}
}
END_TEST
#endif /* (defined HAVE_PCAP_H) || (defined HAVE_PCAP_PCAP_H) */


/*
__attribute__ ((constructor))
static void setup_global(void) / * unchecked * /
{
}
*/

/*
static void teardown_global(void)
{
}
*/

static void setup_file_test(void) /* checked */
{
	FILE *f;

	f = fopen(LNB_TEST_FILENAME, "w");
	if (f != NULL)
	{
		fwrite("aaa", 1, LNB_TEST_FILE_LENGTH, f);
		fclose(f);
	}
}

static void teardown_file_test(void)
{
	unlink(LNB_TEST_FILENAME);
}

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
	Suite * s = suite_create("libnetblock");

	TCase * tests_open = tcase_create("open");
	TCase * tests_exec = tcase_create("exec");
	TCase * tests_net = tcase_create("net");
#if (defined HAVE_PCAP_H) || (defined HAVE_PCAP_PCAP_H)
	TCase * tests_pcap = tcase_create("pcap");
#endif

/* ====================== File functions */

#ifdef HAVE_OPENAT
	tcase_add_test(tests_open, test_openat);
	tcase_add_test(tests_open, test_openat_banned);
# ifdef HAVE_SYMLINK
	tcase_add_test(tests_open, test_openat_link);
	tcase_add_test(tests_open, test_openat_link_banned);
# endif
#endif

	tcase_add_test(tests_open, test_open);
	tcase_add_test(tests_open, test_open_banned);
#ifdef HAVE_SYMLINK
	tcase_add_test(tests_open, test_open_link);
	tcase_add_test(tests_open, test_open_link_banned);
#endif

	tcase_add_test(tests_open, test_fopen);
	tcase_add_test(tests_open, test_fopen_banned);
#ifdef HAVE_SYMLINK
	tcase_add_test(tests_open, test_fopen_link);
	tcase_add_test(tests_open, test_fopen_link_banned);
#endif
	tcase_add_test(tests_open, test_freopen);
	tcase_add_test(tests_open, test_freopen_banned);

#ifdef HAVE_SYMLINK
	tcase_add_test(tests_open, test_freopen_link);
	tcase_add_test(tests_open, test_freopen_link_banned);
#endif


/* ====================== Network functions */

#ifdef HAVE_SYS_SOCKET_H
	tcase_add_test(tests_net, test_socket1);
	tcase_add_test(tests_net, test_socket2);
	tcase_add_test(tests_net, test_socket_banned1);
	tcase_add_test(tests_net, test_socket_banned2);
	tcase_add_test(tests_net, test_socket_banned3);
	tcase_add_test(tests_net, test_socket_banned4);
	tcase_add_test(tests_net, test_socket_banned5);
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

/* ====================== Execution functions */

#ifdef HAVE_UNISTD_H
	/*tcase_add_test(tests_exec, test_execve);*/
	tcase_add_exit_test(tests_exec, test_execve, 0);
	tcase_add_test(tests_exec, test_execve_banned);
#endif
	tcase_add_test(tests_exec, test_system);
	tcase_add_test(tests_exec, test_system_banned);


/* ====================== Packet capture functions */

#if (defined HAVE_PCAP_H) || (defined HAVE_PCAP_PCAP_H)
	tcase_add_test(tests_pcap, test_pcap_create);
	tcase_add_test(tests_pcap, test_pcap_open_live);
#endif

/* ====================== */

	tcase_add_checked_fixture(tests_open, &setup_file_test, &teardown_file_test);
	tcase_add_checked_fixture(tests_exec, &setup_file_test, &teardown_file_test);
	tcase_add_checked_fixture(tests_net, &setup_net_test, &teardown_net_test);

	/* set 30-second timeouts */
	tcase_set_timeout(tests_open, 30);
	tcase_set_timeout(tests_exec, 30);
	tcase_set_timeout(tests_net, 30);
#if (defined HAVE_PCAP_H) || (defined HAVE_PCAP_PCAP_H)
	tcase_set_timeout(tests_pcap, 30);
#endif

	suite_add_tcase(s, tests_open);
	suite_add_tcase(s, tests_exec);
	suite_add_tcase(s, tests_net);
#if (defined HAVE_PCAP_H) || (defined HAVE_PCAP_PCAP_H)
	suite_add_tcase(s, tests_pcap);
#endif

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
