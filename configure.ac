#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.71])
AC_INIT([LibNetBlock], [1.7], [bogdro@users.sourceforge.net], [libnetblock], [https://libnetblock.sourceforge.io])
AM_INIT_AUTOMAKE([-Wall])
AC_CONFIG_FILES([Makefile src/Makefile doc/Makefile test/Makefile
	doc/libnetblock.texi libnetblock.spec src/lnb_cfg.h
	src/libnetblock.h src/lnb_public.c libnetblock.pc])
AC_CONFIG_SRCDIR([src/lnb_net.c])
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_MACRO_DIR([m4])

# ==================== configure arguments

AC_ARG_ENABLE([public-interface],
	AS_HELP_STRING([--enable-public-interface],
		[Enable the library's public interface @<:@default=no@:>@.]),
	[if (test "x$enableval" = "xyes"); then
		public_if=yes
	 else
		public_if=no
	 fi
	]
	,[public_if=no])

AM_CONDITIONAL(PUBLIC_INTERFACE, test "x$public_if" = "xyes")

AC_ARG_ENABLE([environment],
	AS_HELP_STRING([--enable-environment],
		[Enable additional ban files pointed to by environment variables @<:@default=yes@:>@.]),
        [if (test "x$enableval" = "xyes"); then
                environment=yes
         else
                environment=no
         fi
        ]
        ,[environment=yes])

if (test "x$environment" = "xyes"); then

	AC_DEFINE([LNB_ENABLE_ENV], [1],
		[Whether or not to enable additional ban files pointed to by environment variables.])
fi

AC_ARG_ENABLE([user-files],
	AS_HELP_STRING([--enable-user-files],
		[Enable additional ban files located in users' home directories @<:@default=yes@:>@.]),
        [if (test "x$enableval" = "xyes"); then
                user_files=yes
         else
                user_files=no
         fi
        ]
        ,[user_files=yes])

if (test "x$user_files" = "xyes"); then

	AC_DEFINE([LNB_ENABLE_USERBANS], [1],
		[Whether or not to enable additional ban files located in users' home directories.])
fi

#' ==================== Checks for programs.
AC_LANG(C)
AC_PROG_CC
AM_PROG_CC_C_O
AM_PROG_AR
AM_CONDITIONAL(ISGCC, test "x$GCC" = "xyes")
LT_INIT

# ==================== Checks for libraries.
libdl=yes
AC_CHECK_LIB([dl],[dlsym],,[libdl=no])
if (test "x$libdl" = "xyes"); then
	AC_DEFINE([HAVE_LIBDL], [1], [Whether you have the libdl library])
	AC_DEFINE([HAVE_LIBDL_DLSYM], [1], [Whether you have the dlsym() function in the libdl library])
	AC_CHECK_LIB([dl],[dlvsym],[AC_DEFINE([HAVE_LIBDL_DLVSYM], [1],
		[Whether you have the dlvsym() function in the libdl library])])

fi

dlsym=yes
AC_CHECK_FUNC([dlsym],
	[AC_DEFINE([HAVE_DLSYM], [1], [Whether you have the dlsym function])],[dlsym=no])
dlvsym=yes
AC_CHECK_FUNC([dlvsym],
	[AC_DEFINE([HAVE_DLVSYM], [1], [Whether you have the dlvsym function])],[dlvsym=no])

if (test "x$libdl" != "xyes"); then

#	AC_CHECK_FUNCS([dlsym dlvsym])
	if (test "x$dlsym" != "xyes" && test "x$dlvsym" != "xyes"); then

		AC_MSG_ERROR([[I need the dlsym() and optionally dlvsym() function to work.]])
	fi
fi

# Adding additional libraries actually makes LibNetBlock "see" the functions
# contained in them, via dlsym/dlvsym, so the original functions can be called.
# This adds a runtime dependency, but otherwise it could make the program
# bypass LibNetBlock or make normally-working functions not available anymore.

AC_CHECK_LIB([pcap],[pcap_lookupdev])

# ==================== Checks for header files.
AC_CHECK_HEADER([dlfcn.h],[AC_DEFINE([HAVE_DLFCN_H], [1], [Whether you have the dlfcn.h header])],
	AC_MSG_ERROR([[I need the dlfcn.h file to work.]]), [])

AC_CHECK_DECL([RTLD_NEXT],[AC_DEFINE([HAVE_DECL_RTLD_NEXT], [1], [Whether RTLD_NEXT is defined])],
	[echo "**************************************"
	AC_MSG_ERROR([[RTLD_NEXT not defined. Use the GNU C library. Sorry.]])],
	[
	#ifndef _GNU_SOURCE
	#define _GNU_SOURCE	1
	#endif
	#ifdef HAVE_DLFCN_H
	#include <dlfcn.h>
	#endif
	])

# AC_ HEADER_ STDC
# m4_warn([obsolete],
# [The preprocessor macro `STDC_HEADERS' is obsolete.
#   Except in unusual embedded environments, you can safely include all
#   ISO C90 headers unconditionally.])dnl
# Autoupdate added the next two lines to ensure that your configure
# script's behavior did not change.  They are probably safe to remove.
AC_CHECK_INCLUDES_DEFAULT
AC_PROG_EGREP

AC_CHECK_HEADERS([stdlib.h string.h unistd.h errno.h malloc.h \
	sys/types.h sys/socket.h netinet/in.h fcntl.h stdint.h \
	inttypes.h linux/fcntl.h rpc/rpc.h rpc.h])

has_sys_stat_h=yes
AC_CHECK_HEADER([sys/stat.h],AC_DEFINE([HAVE_SYS_STAT_H],[1],
	[Whether you have the sys/stat.h header.]),[has_sys_stat_h=no])

AC_HEADER_STAT

AC_CHECK_HEADER([stdarg.h],AC_DEFINE([HAVE_STDARG_H],[1],
	[Whether you have the stdarg.h header.]),
	[
	AC_CHECK_HEADER([varargs.h],AC_DEFINE([HAVE_VARARGS_H],[1],
		[Whether you have the varargs.h header.]))
	])

AC_CHECK_HEADER(pcap.h,AC_DEFINE([HAVE_PCAP_H],[1],
	[Whether you have the pcap.h header.]),
	[
	AC_CHECK_HEADER([pcap/pcap.h],AC_DEFINE([HAVE_PCAP_PCAP_H],[1],
		[Whether you have the pcap/pcap.h header.]))
	])

# ==================== Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST
AC_C_VOLATILE
AC_TYPE_MODE_T
AC_TYPE_OFF_T
AC_TYPE_SIZE_T
AC_TYPE_SSIZE_T

AC_CHECK_TYPES([socklen_t],,,
	[
	#ifdef HAVE_SYS_TYPES_H
	#include <sys/types.h>
	#endif
	#ifdef HAVE_SYS_SOCKET_H
	#include <sys/socket.h>
	#endif
	])

AC_DEFINE_PATH_STYLE()

# ==================== Checks for library functions.
AC_FUNC_MALLOC
AC_CHECK_FUNC([malloc],
	AC_DEFINE([HAVE_MALLOC],[1],[Whether you have the malloc function.]))

AC_CHECK_FUNCS([memset memcpy readlink getenv openat openat64 lstat symlink \
	execveat fexecve snprintf strdup stat stat64 lstat64 realpath \
	canonicalize_file_name fopen64 freopen64 open64 bindresvport bindresvport6])

have_check=no
#ACTION-IF-NOT-FOUND is required, otherwise 'configure' fails
PKG_CHECK_MODULES([CHECK], [check >= 0.9.8], [have_check=yes], [have_check=no])
#AM_PATH_CHECK([], [have_check=yes])

AM_CONDITIONAL([LNB_TESTS_ENABLED], [test "x$have_check" = "xyes"])

if (test "x$have_check" = "xyes"); then

	AC_CHECK_HEADERS([arpa/inet.h sys/un.h])
fi

# ==================== Checks for compiler options.

if (test "x$GCC" = "xyes" ); then

	AX_GCC_WARN_UNUSED_RESULT()

	AX_C_CHECK_FLAG([-Wall], [CFLAGS="$CFLAGS -Wall"], [CFLAGS="$CFLAGS"])
	AX_C_CHECK_FLAG([-Wextra], [CFLAGS="$CFLAGS -Wextra"], [CFLAGS="$CFLAGS"])
	AX_C_CHECK_FLAG([-W], [CFLAGS="$CFLAGS -W"], [CFLAGS="$CFLAGS"])
	AX_C_CHECK_FLAG([-Wfloat-equal], [CFLAGS="$CFLAGS -Wfloat-equal"], [CFLAGS="$CFLAGS"])
	AX_C_CHECK_FLAG([-Wbad-function-cast], [CFLAGS="$CFLAGS -Wbad-function-cast"], [CFLAGS="$CFLAGS"])
	AX_C_CHECK_FLAG([-Wsign-compare], [CFLAGS="$CFLAGS -Wsign-compare"], [CFLAGS="$CFLAGS"])
	AX_C_CHECK_FLAG([-Wunreachable-code], [CFLAGS="$CFLAGS -Wunreachable-code"], [CFLAGS="$CFLAGS"])
	AX_C_CHECK_FLAG([-Wpointer-arith], [CFLAGS="$CFLAGS -Wpointer-arith"], [CFLAGS="$CFLAGS"])
	AX_C_CHECK_FLAG([-Wcast-qual], [CFLAGS="$CFLAGS -Wcast-qual"], [CFLAGS="$CFLAGS"])
	AX_C_CHECK_FLAG([-Wcast-align], [CFLAGS="$CFLAGS -Wcast-align"], [CFLAGS="$CFLAGS"])
	AX_C_CHECK_FLAG([-Wstrict-prototypes], [CFLAGS="$CFLAGS -Wstrict-prototypes"], [CFLAGS="$CFLAGS"])
	AX_C_CHECK_FLAG([-Wformat -Wformat-security], [CFLAGS="$CFLAGS -Wformat -Wformat-security"], [CFLAGS="$CFLAGS"])
	AX_C_CHECK_FLAG([-Wformat -Wformat-nonliteral], [CFLAGS="$CFLAGS -Wformat -Wformat-nonliteral"], [CFLAGS="$CFLAGS"])
	AX_C_CHECK_FLAG([-Wformat -Wformat-overflow=2], [CFLAGS="$CFLAGS -Wformat -Wformat-overflow=2"], [CFLAGS="$CFLAGS"])
	AX_C_CHECK_FLAG([-Wnested-externs], [CFLAGS="$CFLAGS -Wnested-externs"], [CFLAGS="$CFLAGS"])
	AX_C_CHECK_FLAG([-Wshadow], [CFLAGS="$CFLAGS -Wshadow"], [CFLAGS="$CFLAGS"])
	AX_C_CHECK_FLAG([-Wconversion], [CFLAGS="$CFLAGS -Wconversion"], [CFLAGS="$CFLAGS"])
	AX_C_CHECK_FLAG([-Wdeclaration-after-statement], [CFLAGS="$CFLAGS -Wdeclaration-after-statement"], [CFLAGS="$CFLAGS"])
	AX_C_CHECK_FLAG([-Wundef], [CFLAGS="$CFLAGS -Wundef"], [CFLAGS="$CFLAGS"])
	AX_C_CHECK_FLAG([-Wpadded], [CFLAGS="$CFLAGS -Wpadded"], [CFLAGS="$CFLAGS"])
	AX_C_CHECK_FLAG([-Wredundant-decls], [CFLAGS="$CFLAGS -Wredundant-decls"], [CFLAGS="$CFLAGS"])
	AX_C_CHECK_FLAG([-Wfatal-errors], [CFLAGS="$CFLAGS -Wfatal-errors"], [CFLAGS="$CFLAGS"])
	AX_C_CHECK_FLAG([-pedantic], [CFLAGS="$CFLAGS -pedantic"], [CFLAGS="$CFLAGS"])
	AX_C_CHECK_FLAG([-Wno-strict-aliasing], [CFLAGS="$CFLAGS -Wno-strict-aliasing"], [CFLAGS="$CFLAGS"])
	AX_C_CHECK_FLAG([-Wmissing-prototypes], [CFLAGS="$CFLAGS -Wmissing-prototypes"], [CFLAGS="$CFLAGS"])
	AX_C_CHECK_FLAG([-Wmissing-declarations], [CFLAGS="$CFLAGS -Wmissing-declarations"], [CFLAGS="$CFLAGS"])
	AX_C_CHECK_FLAG([-O1 -Wuninitialized], [CFLAGS="$CFLAGS -O1 -Wuninitialized"], [CFLAGS="$CFLAGS"])
	AX_C_CHECK_FLAG([-Winit-self], [CFLAGS="$CFLAGS -Winit-self"], [CFLAGS="$CFLAGS"])
	AX_C_CHECK_FLAG([-Wlogical-op], [CFLAGS="$CFLAGS -Wlogical-op"], [CFLAGS="$CFLAGS"])
	AX_C_CHECK_FLAG([-fstack-protector-all], [CFLAGS="$CFLAGS -fstack-protector-all"], [CFLAGS="$CFLAGS"])
	AX_C_CHECK_FLAG([-O2], [CFLAGS="$CFLAGS -O2"], [CFLAGS="$CFLAGS"])
	AX_C_CHECK_FLAG([-O3], [CFLAGS="$CFLAGS -O3"], [CFLAGS="$CFLAGS"])
        AX_C_CHECK_FLAG([-Waggregate-return], [CFLAGS="$CFLAGS -Waggregate-return"], [CFLAGS="$CFLAGS"])
        AX_C_CHECK_FLAG([-Wwrite-strings], [CFLAGS="$CFLAGS -Wwrite-strings"], [CFLAGS="$CFLAGS"])
        AX_C_CHECK_FLAG([-Wchkp], [CFLAGS="$CFLAGS -Wchkp"], [CFLAGS="$CFLAGS"])
        AX_C_CHECK_FLAG([-Wduplicated-cond], [CFLAGS="$CFLAGS -Wduplicated-cond"], [CFLAGS="$CFLAGS"])
        AX_C_CHECK_FLAG([-Wrestrict], [CFLAGS="$CFLAGS -Wrestrict"], [CFLAGS="$CFLAGS"])
        AX_C_CHECK_FLAG([-Woverlength-strings], [CFLAGS="$CFLAGS -Woverlength-strings"], [CFLAGS="$CFLAGS"])
        AX_C_CHECK_FLAG([-Wno-nonnull-compare], [CFLAGS="$CFLAGS -Wno-nonnull-compare"], [CFLAGS="$CFLAGS"])
        AX_C_CHECK_FLAG([-Wstringop-truncation], [CFLAGS="$CFLAGS -Wstringop-truncation"], [CFLAGS="$CFLAGS"])
        AX_C_CHECK_FLAG([-Wduplicated-branches], [CFLAGS="$CFLAGS -Wduplicated-branches"], [CFLAGS="$CFLAGS"])
        AX_C_CHECK_FLAG([-fstack-check], [CFLAGS="$CFLAGS -fstack-check"], [CFLAGS="$CFLAGS"])
        AX_C_CHECK_FLAG([-fanalyzer], [CFLAGS="$CFLAGS -fanalyzer"], [CFLAGS="$CFLAGS"])

        # required for the compiler, which is used by libtool instead of the linker
	AX_C_CHECK_FLAG([-Wl,-z -Wl,noexecstack], [CFLAGS="$CFLAGS -Wl,-z -Wl,noexecstack"], [CFLAGS="$CFLAGS"])
	# and just in case the linker was used
	AX_CHECK_LINK_FLAG([-z noexecstack])

fi

# this doubles the CFLAGS on compile:
#AC_SUBST([AM_CFLAGS],[$CFLAGS])

AC_OUTPUT

# ===================== Print summary

echo "***********************************"

if (test "x$public_if" = "xyes"); then

	echo " *	Public interface: yes"

else

	echo " *	Public interface: no (default/disabled by command line)"

fi

if (test "x$environment" = "xyes"); then

	echo " *	Additional ban files pointed to by environment variables: yes"

else

	echo " *	Additional ban files pointed to by environment variables: no (disabled by command line)"

fi

if (test "x$user_files" = "xyes"); then

	echo " *	Additional ban files located in users' home directories: yes"

else

	echo " *	Additional ban files located in users' home directories: no (disabled by command line)"

fi

echo "***********************************"
