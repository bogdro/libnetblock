/*
 * LibNetBlock - A library which blocks programs from accessing the network.
 *	-- private header file.
 *
 * Copyright (C) 2011-2024 Bogdan Drozdowski, bogdro (at) users . sourceforge . net
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

#ifndef _LNB_HEADER
# define _LNB_HEADER 1

# include "lnb_cfg.h"

# ifdef LNB_ATTR
#  undef LNB_ATTR
# endif
# ifdef __GNUC__
#  define LNB_ATTR(x)	__attribute__(x)
# else
#  define LNB_ATTR(x)
# endif

# ifndef GCC_WARN_UNUSED_RESULT
/*
 if the compiler doesn't support this, define this to an empty string,
 so that everything compiles (just in case)
 */
#  define GCC_WARN_UNUSED_RESULT /*LNB_ATTR((warn_unused_result))*/
# endif

/* LNB_PARAMS is a macro used to wrap function prototypes, so that
        compilers that don't understand ANSI C prototypes still work,
        and ANSI C compilers can issue warnings about type mismatches. */
# ifdef LNB_PARAMS
#  undef LNB_PARAMS
# endif
# if defined (__STDC__) || defined (_AIX) \
	|| (defined (__mips) && defined (_SYSTYPE_SVR4)) \
	|| defined (WIN32) || defined (__cplusplus)
#  define LNB_PARAMS(protos) protos
#  define LNB_ANSIC
# else
#  define LNB_PARAMS(protos) ()
#  undef LNB_ANSIC
# endif

# ifdef __GNUC__
#  ifndef strcat
#   pragma GCC poison strcat
#  endif
#  ifndef strcpy
#   pragma GCC poison strcpy
#  endif
# endif

# include <stdio.h>		/* FILE */

# ifdef HAVE_SYS_TYPES_H
#  include <sys/types.h>	/* size_t */
# endif

# ifdef HAVE_STDLIB_H
#  include <stdlib.h>		/* sys/socket.h */
# endif

# ifdef HAVE_SYS_SOCKET_H
#  include <sys/socket.h>
# else
#  ifndef HAVE_SOCKLEN_T
typedef int socklen_t;
#  endif
# endif

# ifdef HAVE_INTTYPES_H
#  include <inttypes.h>	/* intptr_t */
# endif

# ifdef HAVE_STDINT_H
#  include <stdint.h>	/* intptr_t */
# endif

#ifdef HAVE_NETINET_IN_H
# include <netinet/in.h>
#endif

# if (!defined HAVE_OFF64_T) && (!defined LNB_OFF64_T_DEFINED)
#  ifdef HAVE_LONG_LONG_INT
typedef long long int off64_t;
#  else
typedef long int off64_t;
#  endif
#  define LNB_OFF64_T_DEFINED 1
# endif

# if (!defined HAVE_INTPTR_T) && (!defined LNB_INTPTR_T_DEFINED)
typedef unsigned int intptr_t;
#  define LNB_INTPTR_T_DEFINED 1
# endif

# ifdef HAVE_PCAP_H
#  include <pcap.h>
# else
#  ifdef HAVE_PCAP_PCAP_H
#   include <pcap/pcap.h>
#  else
/* can't find neither pcap.h nor pcap/pcap.h - make up our own declarations: */
typedef void pcap_t;
typedef void pcap_if_t;
typedef unsigned int bpf_u_int32;
#  endif
# endif

/* --- Function typedefs. */
/* program execution functions: */
typedef int (*i_cp_cpp_cpp)			LNB_PARAMS ((const char *filename, char *const argv[],
							char *const envp[]));
typedef int (*i_i_cpp_cpp)			LNB_PARAMS ((int fd, char *const argv[],
							char *const envp[]));
typedef int (*i_i_cp_cpp_cpp_i)			LNB_PARAMS ((int dirfd, const char *filename,
							char *const argv[], char *const envp[], int flags));
typedef int (*i_cp)				LNB_PARAMS ((const char *command));

/* network-related functions: */
typedef int (*i_i_i_i)				LNB_PARAMS ((int domain, int type, int protocol));
typedef ssize_t (*ss_i_smp_i)			LNB_PARAMS ((int s, struct msghdr *msg, int flags));
typedef ssize_t (*ss_i_csmp_i)			LNB_PARAMS ((int s, const struct msghdr *msg, int flags));
typedef int (*i_cssp_sl)			LNB_PARAMS ((int sockfd, const struct sockaddr *my_addr,
							socklen_t addrlen));
typedef int (*i_i_ia2)				LNB_PARAMS ((int d, int type, int protocol, int sv[2]));
typedef int (*i_i_ssa)				LNB_PARAMS ((int s, struct sockaddr_in *sin));
typedef int (*i_i_ssa6)				LNB_PARAMS ((int s, struct sockaddr_in6 *sin));

/* file-related functions: */
typedef FILE*	(*fp_cp_cp)			LNB_PARAMS ((const char * const name, const char * const mode));
typedef FILE*	(*fp_cp_cp_fp)			LNB_PARAMS ((const char * const name, const char * const mode,
							FILE* stream));
typedef int	(*i_cp_i_)			LNB_PARAMS ((const char * const name, const int flags, ...));
typedef int	(*i_i_cp_i_)			LNB_PARAMS ((const int dir_fd, const char * const pathname,
							const int flags, ...));

/* libpcap functions: */
typedef pcap_t * (*pp_ccp_cp)			LNB_PARAMS ((const char * source, char * errbuf));
typedef pcap_t * (*pp_ccp_i_i_i_cp)		LNB_PARAMS ((const char * device, int snaplen,
							int promisc, int to_ms, char * errbuf));

# ifdef __cplusplus
extern "C" {
# endif

/* program execution functions: */
extern GCC_WARN_UNUSED_RESULT i_cp_cpp_cpp	__lnb_real_execve_location LNB_PARAMS ((void));
extern GCC_WARN_UNUSED_RESULT i_i_cpp_cpp	__lnb_real_fexecve_location LNB_PARAMS ((void));
extern GCC_WARN_UNUSED_RESULT i_i_cp_cpp_cpp_i	__lnb_real_execveat_location LNB_PARAMS ((void));
extern GCC_WARN_UNUSED_RESULT i_cp		__lnb_real_system_location LNB_PARAMS ((void));

/* network-related functions: */
extern GCC_WARN_UNUSED_RESULT i_i_i_i		__lnb_real_socket_location LNB_PARAMS ((void));
extern GCC_WARN_UNUSED_RESULT ss_i_smp_i	__lnb_real_recvmsg_location LNB_PARAMS ((void));
extern GCC_WARN_UNUSED_RESULT ss_i_csmp_i	__lnb_real_sendmsg_location LNB_PARAMS ((void));
extern GCC_WARN_UNUSED_RESULT i_cssp_sl		__lnb_real_bind_location LNB_PARAMS ((void));
extern GCC_WARN_UNUSED_RESULT i_i_ssa		__lnb_real_bindresvport_loc LNB_PARAMS ((void));
extern GCC_WARN_UNUSED_RESULT i_i_ssa6		__lnb_real_bindresvport6_loc LNB_PARAMS ((void));

/* file-related functions: */
extern GCC_WARN_UNUSED_RESULT fp_cp_cp		__lnb_real_fopen64_location LNB_PARAMS ((void));
extern GCC_WARN_UNUSED_RESULT fp_cp_cp_fp	__lnb_real_freopen64_location LNB_PARAMS ((void));
extern GCC_WARN_UNUSED_RESULT i_cp_i_		__lnb_real_open64_location LNB_PARAMS ((void));
extern GCC_WARN_UNUSED_RESULT i_i_cp_i_		__lnb_real_openat64_location LNB_PARAMS ((void));

extern GCC_WARN_UNUSED_RESULT fp_cp_cp		__lnb_real_fopen_location LNB_PARAMS ((void));
extern GCC_WARN_UNUSED_RESULT fp_cp_cp_fp	__lnb_real_freopen_location LNB_PARAMS ((void));
extern GCC_WARN_UNUSED_RESULT i_cp_i_		__lnb_real_open_location LNB_PARAMS ((void));
extern GCC_WARN_UNUSED_RESULT i_i_cp_i_		__lnb_real_openat_location LNB_PARAMS ((void));

/* libpcap functions: */
extern GCC_WARN_UNUSED_RESULT pp_ccp_cp		__lnb_real_pcap_create_location LNB_PARAMS ((void));
extern GCC_WARN_UNUSED_RESULT pp_ccp_i_i_i_cp	__lnb_real_pcap_open_live_loc LNB_PARAMS ((void));

/* The library functions: */
extern int					__lnb_main LNB_PARAMS ((void));
extern int GCC_WARN_UNUSED_RESULT		__lnb_check_prog_ban LNB_PARAMS ((void));
extern int GCC_WARN_UNUSED_RESULT		__lnb_is_forbidden_file
							LNB_PARAMS ((const char * const name));
extern int GCC_WARN_UNUSED_RESULT		__lnb_get_init_stage LNB_PARAMS ((void));



# ifdef HAVE_MEMCPY
#  define LNB_MEMCOPY memcpy
# else
extern void __lnb_memcopy LNB_PARAMS ((void * const dest,
	const void * const src, const size_t len));
#  define LNB_MEMCOPY __lnb_memcopy
# endif

# ifdef HAVE_MEMSET
#  define LNB_MEMSET memset
# else
extern void __lnb_mem_set LNB_PARAMS ((void * const dest,
	const char value, const size_t len));
#  define LNB_MEMSET __lnb_mem_set
# endif

# ifdef HAVE_STRDUP
#  define LNB_STRDUP strdup
# else
extern char * __lnb_duplicate_string LNB_PARAMS ((const char src[]));
#  define LNB_STRDUP __lnb_duplicate_string
# endif

extern void __lnb_copy_string LNB_PARAMS ((char * const dest,
	const char src[], const size_t len));		/* lnb_main.c */

# ifdef __cplusplus
}
# endif

# if (PATH_STYLE==32) || (PATH_STYLE==128)	/* unix or mac */
#  define LNB_PATH_SEP "/"
#  define LNB_FILE_SEP ':'
# else
#  define LNB_PATH_SEP "\\"
#  define LNB_FILE_SEP ';'
# endif

# define LNB_MAX(a, b) ( ((a) > (b)) ? (a) : (b) )
# define LNB_MIN(a, b) ( ((a) < (b)) ? (a) : (b) )
# define LNB_MAXPATHLEN 4097
# define LNB_INIT_STAGE_NOT_INITIALIZED 0
# define LNB_INIT_STAGE_FULLY_INITIALIZED 2

# ifdef HAVE_ERRNO_H
#  ifdef ENOSYS
#   define LNB_SET_ERRNO_MISSING() do {errno = ENOSYS;} while (0)
#  else
#   define LNB_SET_ERRNO_MISSING() do {errno = 38;} while (0)
#  endif
#  define LNB_SET_ERRNO_PERM() do {errno = EPERM;} while (0)
#  define LNB_SET_ERRNO(value) do {errno = value;} while (0)
#  define LNB_GET_ERRNO(variable) do {variable = errno;} while (0)
#  define LNB_MAKE_ERRNO_VAR(name) int name = errno
# else
#  define LNB_SET_ERRNO_MISSING()
#  define LNB_SET_ERRNO_PERM()
#  define LNB_SET_ERRNO(value)
#  define LNB_GET_ERRNO(variable)
#  define LNB_MAKE_ERRNO_VAR(name)
# endif

# if (defined __GNUC__) && (defined __GLIBC__) && (defined __GLIBC_MINOR__)
#  if (__GLIBC__ == 2) && (__GLIBC_MINOR__ == 11)
#   warning x
#   warning x Glibc version 2.11 has a bug in dl(v)sym. Read the documentation.
#   warning x
#  endif
# endif

# ifdef LNB_ANSIC
#  define LNB_VOID void
# else
#  define LNB_VOID
# endif

#endif /* _LNB_HEADER */
