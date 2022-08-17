/*
 * A library library which blocks programs from accessing the network.
 *	-- execution functions' replacements.
 *
 * Copyright (C) 2011-2019 Bogdan Drozdowski, bogdandr (at) op.pl
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
#define _XOPEN_SOURCE 500
#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE 1
#define _ATFILE_SOURCE 1
#define _GNU_SOURCE 1

#ifdef HAVE_UNISTD_H
# include <unistd.h>	/* execve(), readlink() */
#endif

#ifdef HAVE_ERRNO_H
# include <errno.h>
#endif

#include <stdio.h>	/* stdlib.h */

#ifdef HAVE_STDLIB_H
# include <stdlib.h>	/* system(), getenv() */
#endif

#ifdef HAVE_MALLOC_H
# include <malloc.h>
#endif

#ifdef HAVE_SYS_STAT_H
# ifdef STAT_MACROS_BROKEN
#  if STAT_MACROS_BROKEN
#   error Stat macros broken. Change your C library.
#  endif
# endif
# include <sys/stat.h>
#endif

#ifdef HAVE_STRING_H
# if (!defined STDC_HEADERS) && (defined HAVE_MEMORY_H)
#  include <memory.h>
# endif
# include <string.h>
#endif

#include "lnb_priv.h"

/* The programs LibNetBlock forbids to execute. */
static const char *programs[] =
{
	"ping",
	"traceroute",
	"tracert",
	"dig",
	"nmap",
	"nessus",
	"ifconfig",
	"ifcfg",
	"nc",
	"netcat",
	"ftp",
	"links",
	"lynx",
	"wget",
	"host",
	"hostname",
	"uname",
	"arp",
	"netstat",
	"domainname",
	"ipmaddr",
	"mii",
	"route",
	"ifdown",
	"ifup",
	"iftop",
	"tcp",
	"ppp",
	"isdn",
	"ssh",
	"telnet",
	"rsh",
	"ntop",
	"sniff",
	"shark"
};

/* The programs LibNetBlock conditionally forbids to execute (when they're
   used to get the content of important files). */
static const char * viewing_programs[] =
{
	/* plain viewers: */
	"cat",
	"type",
	"tac",
	"less",
	"more",

	/* editors: */
	"vi",	/* also mathes "vim" */
	"emacs",
	"joe",
	"jed",
	"lpe",
	"pico",
	"hexedit",

	/* textutils: */
	"nl",
	"od",
	"fmt",
	"pr",
	"fold",
	"head",
	"tail",
	"split",	/* also mathes "csplit" */
	"sort",
	"uniq",
	"comm",
	"cut",
	"paste",
	"join",
	"tr",
	"expand",	/* also mathes "unexpand" */

	/* diff tools: */
	"diff",		/* also mathes "diff3" and "sdiff" */

	/* text programming/manipulation tools and interpreters: */
	"ed",		/* matches "sed", too */
	"awk",		/* matches "nawk" and "gawk", too */
	"perl",
	"python",
	"ruby",
	"lua",
	"php",
	"tcl",
	"gcl",
	"sbcl",
	"lisp",

	/* shells (blocking "sh" can catch too many programs): */
	"bash",
	"zsh",
	"csh",
	"ksh"
};

static const char * __lnb_valuable_files[] =
{
	"if_inet6",
	"ipv6_route",
	"hosts",
	"ifcfg-",
	"hostname",
	"mactab",
	"/dev/net",
	"/dev/udp",
	"/dev/tcp"
};

#ifndef HAVE_MALLOC
static char __lnb_linkpath[LNB_MAXPATHLEN + 1];
static char __lnb_newlinkpath[LNB_MAXPATHLEN + 1];
#endif

#ifdef __cplusplus
extern "C" {
#endif

#ifndef HAVE_EXECVEAT
extern int execveat LNB_PARAMS ((int dirfd, const char *pathname,
	char *const argv[], char *const envp[], int flags));
#endif
#ifndef HAVE_FEXECVE
extern int fexecve LNB_PARAMS ((int fd, char *const argv[], char *const envp[]));
#endif

#ifdef __cplusplus
}
#endif

/* =============================================================== */

#ifndef LNB_ANSIC
static char * __lnb_get_target_link_path
	LNB_PARAMS ((char * const name));
#endif

/**
 * Gets the final target object name of the given link (the name of the
 *  first object being pointed to, which is not a link).
 * \param name The name of the link to traverser.
 * \return The real target's name.
 */
static char * __lnb_get_target_link_path (
#ifdef LNB_ANSIC
	char * const name)
#else
	name)
	char * const name;
#endif
{
#if (defined HAVE_SYS_STAT_H) && (defined HAVE_READLINK) && (defined HAVE_LSTAT)
	int res;
	ssize_t lnk_res;
	char * current_name;
	off_t lsize;
	struct stat st;
# ifdef HAVE_MALLOC
	char * __lnb_newlinkpath;
	char * __lnb_newlinkdir;
# endif
	char * last_slash;
	size_t dirname_len;

	if ( name == NULL )
	{
		return NULL;
	}

	current_name = LNB_STRDUP (name);
	if ( current_name != NULL )
	{
		res = lstat (current_name, &st);
		while ( res >= 0 )
		{
			if ( ! S_ISLNK (st.st_mode) )
			{
				break;
			}
			lsize = st.st_size;
			if ( lsize <= 0 )
			{
				break;
			}
			/* in case the link's target is a relative path,
			prepare to prepend the link's directory name */
			last_slash = rindex (current_name, '/');
			if ( last_slash != NULL )
			{
				dirname_len = (size_t)(last_slash - current_name);
			}
			else
			{
				dirname_len = 0;
			}
# ifdef HAVE_MALLOC
			__lnb_newlinkpath = (char *) malloc ((size_t)(
				dirname_len + 1
				+ (size_t)lsize + 1));
			if ( __lnb_newlinkpath == NULL )
			{
				break;
			}
# else /* ! HAVE_MALLOC */
			lsize = sizeof (__lnb_newlinkpath);
# endif /* HAVE_MALLOC */
			LNB_MEMSET (__lnb_newlinkpath, 0, (size_t)lsize);
			lnk_res = readlink (current_name, __lnb_newlinkpath, (size_t)lsize);
			if ( (lnk_res < 0) || (lnk_res > lsize) )
			{
				break;
			}
			__lnb_newlinkpath[lnk_res] = '\0';
			if ( (__lnb_newlinkpath[0] != '/') && (dirname_len > 0) )
			{
				/* The link's target is a relative path (no slash) in a
				different directory (there was a slash in the original path)
				- append the link's directory name */
# ifdef HAVE_MALLOC
				__lnb_newlinkdir = (char *) malloc ((size_t)(
					dirname_len + 1
					+ (size_t)lsize + 1));
				if ( __lnb_newlinkdir == NULL )
				{
					free (__lnb_newlinkpath);
					break;
				}
# endif /* HAVE_MALLOC */
				strncpy (__lnb_newlinkdir, current_name, dirname_len);
				__lnb_newlinkdir[dirname_len] = '/';
				__lnb_newlinkdir[dirname_len + 1] = '\0';
				strncat (__lnb_newlinkdir, __lnb_newlinkpath,
					(size_t)lsize + 1);
				__lnb_newlinkdir[dirname_len + 1
					+ (size_t)lsize] = '\0';
				strncpy (__lnb_newlinkpath, __lnb_newlinkdir,
					dirname_len + 1 + (size_t)lsize + 1);
				__lnb_newlinkpath[dirname_len + 1 +
					(size_t)lsize] = '\0';
# ifdef HAVE_MALLOC
				free (__lnb_newlinkdir);
# endif /* HAVE_MALLOC */
			}
# ifdef HAVE_MALLOC
			free (current_name);
# endif /* HAVE_MALLOC */
			current_name = __lnb_newlinkpath;
			res = lstat (current_name, &st);
		}
		return current_name;
	}
	else
	{
		/* memory not allocated - return the original */
		return name;
	}
#else
	return name;
#endif /* (defined HAVE_SYS_STAT_H) && (defined HAVE_READLINK) && (defined HAVE_LSTAT) */
}

/* ======================================================= */

#ifndef LNB_ANSIC
static char * __lnb_get_target_link_path_fd
	LNB_PARAMS ((const int fd));
#endif

/**
 * Gets the final target object name of the given link (the name of the
 *  first object being pointed to, which is not a link).
 * \param name The name of the link to traverser.
 * \return The real target's name.
 */
static char * __lnb_get_target_link_path_fd (
#ifdef LNB_ANSIC
	const int fd)
#else
	fd)
	const int fd;
#endif
{
	/* strlen(/proc) + strlen(/self) + strlen(/fd/) + strlen(maxint) + '\0' */
	char linkpath[5 + 5 + 4 + 10 + 1];

	if ( fd < 0 )
	{
		return NULL;
	}
#ifdef HAVE_SNPRINTF
	snprintf (linkpath, sizeof(linkpath) - 1, "/proc/self/fd/%d", fd);
#else
	sprintf (linkpath, "/proc/self/fd/%d", fd);
#endif
	linkpath[sizeof(linkpath) - 1] = '\0';
	return __lnb_get_target_link_path (linkpath);
}

/* =============================================================== */

/**
 * Tells if the file with the given name is forbidden to be opened.
 * \param name The name of the file to check.
 * \return 1 if forbidden, 0 otherwise.
 */
int __lnb_is_forbidden_file (
#ifdef LNB_ANSIC
	const char * const name)
#else
	name)
	const char * const name;
#endif
{
#ifdef HAVE_MALLOC
	char * __lnb_linkpath;
	char * name_copy;
#endif
	unsigned int j;
	int ret = 0;

	if ( name == NULL )
	{
		return 0;
	}
#ifdef HAVE_MALLOC
	name_copy = LNB_STRDUP (name);
	if ( name_copy == NULL )
	{
		return 0;
	}
	__lnb_linkpath = __lnb_get_target_link_path (name_copy);
#else
	strncpy (__lnb_linkpath, name, sizeof (__lnb_linkpath)-1);
	strncpy (__lnb_linkpath, __lnb_get_target_link_path (__lnb_linkpath), sizeof (__lnb_linkpath)-1);
	__lnb_linkpath[sizeof (__lnb_linkpath) - 1] = '\0';
#endif
	for ( j = 0; j < sizeof (__lnb_valuable_files)/sizeof (__lnb_valuable_files[0]); j++)
	{
		if ( strstr (__lnb_linkpath, __lnb_valuable_files[j]) != NULL )
		{
			ret = 1;
			break;
		}
	}
#ifdef HAVE_MALLOC
	free (name_copy);
	if ( (__lnb_linkpath != NULL) && (__lnb_linkpath != name) )
	{
		free ((void *)__lnb_linkpath);
	}
#endif
	return ret;
}

/* =============================================================== */

#ifndef LNB_ANSIC
static void __lnb_append_path
	LNB_PARAMS ((char * const path, const char * const name, const size_t path_size));
#endif

/**
 * Appends the given element to the given path.
 * \param path The path to append to.
 * \param name The element to append.
 * \param path_size the size of the "path" array/pointer
 */
static void __lnb_append_path (
#ifdef LNB_ANSIC
	char * const path, const char * const name, const size_t path_size)
#else
	path, name, path_size)
	char * const path;
	const char * const name;
	const size_t path_size;
#endif
{
	size_t path_len;
	size_t sep_len;
	size_t name_len;

	if ( (path == NULL) || (name == NULL) || (path_size == 0) )
	{
		return;
	}

	path_len = strlen (path);
	sep_len = strlen (LNB_PATH_SEP);
	name_len = strlen (name);

	strncat (path, LNB_PATH_SEP,
		LNB_MIN (path_size - path_len - 1, sep_len));
	strncat (path, name,
		LNB_MIN (path_size - path_len - 1, name_len));
	path[path_size-1] = '\0';
}

/* =============================================================== */

#ifndef LNB_ANSIC
static int __lnb_is_forbidden_program
	LNB_PARAMS ((const char * const name, char *const argv[], const int is_system));
#endif

#if (defined HAVE_SYS_STAT_H) && (defined HAVE_READLINK)
# define LNB_ONLY_WITH_STAT_AND_READLINK
#else
# define LNB_ONLY_WITH_STAT_AND_READLINK LNB_ATTR ((unused))
#endif

/**
 * Tells if the program with the given name is forbidden to run.
 * \param name The name of the program to check.
 * \param argv The command-line arguments of the program (in case of exec*()).
 * \param is_system Non-zero in case of a check for the system() function.
 * \return 1 if forbidden, 0 otherwise.
 */
static int __lnb_is_forbidden_program (
#ifdef LNB_ANSIC
	const char * const name, char *const argv[],
	const int is_system LNB_ONLY_WITH_STAT_AND_READLINK
	)
#else
	name, argv, is_system)
	const char * const name;
	char *const argv[];
	const int is_system LNB_ONLY_WITH_STAT_AND_READLINK;
#endif
{
#ifdef HAVE_MALLOC
	char * __lnb_linkpath = NULL;
#endif
#if (defined HAVE_SYS_STAT_H) && (defined HAVE_READLINK)
	int res;
	struct stat st;
	char *first_char = NULL;
# if (defined HAVE_GETENV) && (defined HAVE_SYS_STAT_H)
	char *path = NULL;
#  ifdef HAVE_MALLOC
	char *path_dir = NULL;
#  endif
# endif
#endif
	size_t i, j;
	unsigned int k;
	int ret = 0;

	if ( name == NULL )
	{
		return 0;
	}

#ifdef HAVE_MALLOC
	j = strlen (name);
	j = LNB_MAX (LNB_MAXPATHLEN, j);
	__lnb_linkpath = (char *) malloc (j + 1);
	if ( __lnb_linkpath != NULL )
#else
	j = LNB_MAXPATHLEN;
#endif
	{
		for ( i = 0; i < j + 1; i++ )
		{
			__lnb_linkpath[i] = '\0';
		}

		strncpy (__lnb_linkpath, name, j);
		__lnb_linkpath[j] = '\0';
#if (defined HAVE_SYS_STAT_H) && (defined HAVE_READLINK)
		if ( is_system )
		{
			/* system() call - find the full path of the program to run.
			   If space is not found, then 'name' is the full program
			   name and it's already copied to '__lnb_linkpath' */
			first_char = strchr (name, ' ');
			if ( first_char != NULL )
			{
				/* space found - copy everything before it as the program name */
				strncpy (__lnb_linkpath, name,
					LNB_MIN ((size_t)(first_char - name), j));
				__lnb_linkpath[first_char - name] = '\0';
			}
			__lnb_linkpath[j] = '\0';
			if ( strncmp (__lnb_linkpath, LNB_PATH_SEP, strlen(LNB_PATH_SEP)) != 0 )
			{
				/* add path, so we have the full path to the object and can check its type. */
# if (defined HAVE_GETENV) && (defined HAVE_SYS_STAT_H)
				path = getenv ("PATH");
				if ( path != NULL )
				{
					first_char = strchr (path, LNB_FILE_SEP);
#  if (defined HAVE_MALLOC)
					if ( first_char != NULL )
					{
						path_dir = (char *) malloc (j + 1);
						if ( path_dir != NULL )
						{
							for ( i = 0; i < j + 1; i++ )
							{
								path_dir[i] = '\0';
							}

							do
							{
								strncpy (path_dir, path,
									LNB_MIN ((size_t)(first_char - path), j));
								path_dir[LNB_MIN ((size_t)(first_char - path), j)]
									= '\0';
								__lnb_append_path (path_dir, __lnb_linkpath, j);
								path_dir[j] = '\0';
								res = stat (path_dir, &st);
								if ( res >= 0 )
								{
									break;	/* object was found */
								}
								path = &first_char[1];
								first_char = strchr (path, LNB_FILE_SEP);

							} while ( first_char != NULL );
						}
					}
					else
					{
						path_dir = (char *) malloc (
							strlen (path) + 1 + strlen (__lnb_linkpath) + 1);
						if ( path_dir != NULL )
						{
							strncpy (path_dir, path, strlen (path) + 1);
							path_dir[strlen (path) + 1] = '\0';
							__lnb_append_path (path_dir, __lnb_linkpath, j);
							path_dir[strlen (path) + 1 + strlen (__lnb_linkpath)] = '\0';
						}
					}
					/* path_dir, if not NULL, contains "PATH/name" */
					if ( path_dir != NULL )
					{
						strncpy (__lnb_linkpath, path_dir, j);
						__lnb_linkpath[j] = '\0';
						free (path_dir);
					}
#  else
					if ( first_char != NULL )
					{
						strncpy (__lnb_newlinkpath, path,
							LNB_MIN ((size_t)(first_char - path),
							sizeof (__lnb_newlinkpath) - 1));
						__lnb_newlinkpath[LNB_MIN ((size_t)(first_char - path),
							sizeof (__lnb_newlinkpath) - 1)] = '\0';
					}
					else
					{
						strncpy (__lnb_newlinkpath, path,
							sizeof (__lnb_newlinkpath) - 1);
						__lnb_newlinkpath[sizeof (__lnb_newlinkpath) - 1] = '\0';
					}
					__lnb_append_path (__lnb_newlinkpath,
						__lnb_linkpath, sizeof (__lnb_newlinkpath));
					__lnb_newlinkpath[sizeof (__lnb_newlinkpath) - 1] = '\0';
					strncpy (__lnb_linkpath, __lnb_newlinkpath,
						sizeof (__lnb_newlinkpath) - 1);
					__lnb_linkpath[sizeof (__lnb_linkpath) - 1] = '\0';
#  endif
				}
# endif /* (defined HAVE_GETENV) && (defined HAVE_SYS_STAT_H) */
			} /* if (path is not absolute) */
		} /* if is_system */
# ifdef HAVE_MALLOC
		first_char = __lnb_get_target_link_path (__lnb_linkpath);
		free ((void *)__lnb_linkpath);
		__lnb_linkpath = first_char;
# else
		strncpy (__lnb_linkpath, __lnb_get_target_link_path (__lnb_linkpath),
			sizeof (__lnb_linkpath)-1);
		__lnb_linkpath[sizeof (__lnb_linkpath) - 1] = '\0';
# endif
#endif /* (defined HAVE_SYS_STAT_H) && (defined HAVE_READLINK) */
		for ( j = 0; j < sizeof (programs)/sizeof (programs[0]); j++)
		{
			if ( strstr (name, programs[j]) != NULL )
			{
				ret = 1;
				break;
			}
			if ( strstr (__lnb_linkpath, programs[j]) != NULL )
			{
				ret = 1;
				break;
			}
		}
		if ( (argv != NULL) && (ret == 0) )
		{
			/*
			now check if the viewing programs aren't used to get the contents
			of valuable files like /etc/hosts
			*/
			for ( i = 0; (ret == 0)
				&& (i < sizeof (viewing_programs)/sizeof (viewing_programs[0])); i++)
			{
				if ( strstr (__lnb_linkpath, viewing_programs[i]) != NULL )
				{
					k = 0;
					while ( (argv[k] != NULL) && (ret == 0) )
					{
						if ( __lnb_is_forbidden_file (argv[k]) != 0 )
						{
							ret = 1;
							break;
						}
						k++;
					}
				}
			}
		}
		if ( (ret == 0) && (__lnb_is_forbidden_file (__lnb_linkpath) != 0) )
		{
			ret = 1;
		}
	} /* if ( __lnb_linkpath != NULL && __lnb_newlinkpath != NULL ) */
#ifdef HAVE_MALLOC
	if ( (__lnb_linkpath != NULL) && (__lnb_linkpath != name) )
	{
		free ((void *)__lnb_linkpath);
	}
#endif
	return ret;
}

/* =============================================================== */

int
execve (
#ifdef LNB_ANSIC
	const char *filename, char *const argv[], char *const envp[])
#else
	filename, argv, envp)
	const char *filename;
	char *const argv[];
	char *const envp[];
#endif
{
	LNB_MAKE_ERRNO_VAR(err);

	__lnb_main ();
#ifdef LNB_DEBUG
	fprintf (stderr, "libnetblock: execve(%s)\n", (filename==NULL)? "null" : filename);
	fflush (stderr);
#endif

	if ( __lnb_real_execve_location () == NULL )
	{
		LNB_SET_ERRNO_MISSING();
		return -1;
	}

	if ( filename == NULL )
	{
		LNB_SET_ERRNO(err);
		return (*__lnb_real_execve_location ()) (filename, argv, envp);
	}

	if ( (__lnb_check_prog_ban () != 0)
		|| (__lnb_get_init_stage () < LNB_INIT_STAGE_FULLY_INITIALIZED) )
	{
		LNB_SET_ERRNO(err);
		return (*__lnb_real_execve_location ()) (filename, argv, envp);
	}

	if ( __lnb_is_forbidden_program (filename, argv, 0) != 0 )
	{
		LNB_SET_ERRNO_PERM();
		return -1;
	}
	return (*__lnb_real_execve_location ()) (filename, argv, envp);
}

/* =============================================================== */

int
fexecve (
#ifdef LNB_ANSIC
	int fd, char *const argv[], char *const envp[])
#else
	fd, argv, envp)
	int fd;
	char *const argv[];
	char *const envp[];
#endif
{
	char * real_name;
	int res;
	LNB_MAKE_ERRNO_VAR(err);

	__lnb_main ();
#ifdef LNB_DEBUG
	fprintf (stderr, "libnetblock: fexecve(%d)\n", fd);
	fflush (stderr);
#endif

	if ( __lnb_real_fexecve_location () == NULL )
	{
		LNB_SET_ERRNO_MISSING();
		return -1;
	}

	if ( (__lnb_check_prog_ban () != 0)
		|| (__lnb_get_init_stage() < LNB_INIT_STAGE_FULLY_INITIALIZED) )
	{
		LNB_SET_ERRNO(err);
		return (*__lnb_real_fexecve_location ()) (fd, argv, envp);
	}

	real_name = __lnb_get_target_link_path_fd (fd);
	if ( real_name != NULL )
	{
		res = __lnb_is_forbidden_program (real_name, argv, 0);
		if ( res != 0 )
		{
#ifdef HAVE_MALLOC
			free ((void *)real_name);
#endif
			LNB_SET_ERRNO_PERM();
			return -1;
		}
	}
	return (*__lnb_real_fexecve_location ()) (fd, argv, envp);
}

/* =============================================================== */

int
execveat (
#ifdef LNB_ANSIC
	int dirfd, const char *filename, char *const argv[], char *const envp[], int flags)
#else
	dirfd, filename, argv, envp, flags)
	int dirfd;
	const char *filename;
	char *const argv[];
	char *const envp[];
	int flags;
#endif
{
	LNB_MAKE_ERRNO_VAR(err);

	__lnb_main ();
#ifdef LNB_DEBUG
	fprintf (stderr, "libnetblock: execveat(%d, %s)\n", dirfd,
		(filename == NULL)? "null" : filename);
	fflush (stderr);
#endif

	if ( __lnb_real_execveat_location () == NULL )
	{
		LNB_SET_ERRNO_MISSING();
		return -1;
	}

	if ( filename == NULL )
	{
		LNB_SET_ERRNO(err);
		return (*__lnb_real_execveat_location ()) (dirfd, filename, argv, envp, flags);
	}

	if ( (__lnb_check_prog_ban () != 0)
		|| (__lnb_get_init_stage() < LNB_INIT_STAGE_FULLY_INITIALIZED) )
	{
		LNB_SET_ERRNO(err);
		return (*__lnb_real_execveat_location ()) (dirfd, filename, argv, envp, flags);
	}

	if ( __lnb_is_forbidden_program (filename, argv, 0) != 0 )
	{
		LNB_SET_ERRNO_PERM();
		return -1;
	}
	return (*__lnb_real_execveat_location ()) (dirfd, filename, argv, envp, flags);
}

/* =============================================================== */

int
system (
#ifdef LNB_ANSIC
	const char *command)
#else
	command)
	const char *command;
#endif
{
	LNB_MAKE_ERRNO_VAR(err);

	__lnb_main ();
#ifdef LNB_DEBUG
	fprintf (stderr, "libnetblock: system(%s)\n", (command==NULL)? "null" : command);
	fflush (stderr);
#endif

	if ( __lnb_real_system_location () == NULL )
	{
		LNB_SET_ERRNO_MISSING();
		return -1;
	}

	if ( command == NULL )
	{
		LNB_SET_ERRNO(err);
		return (*__lnb_real_system_location ()) (command);
	}

	if ( (__lnb_check_prog_ban () != 0)
		|| (__lnb_get_init_stage () < LNB_INIT_STAGE_FULLY_INITIALIZED) )
	{
		LNB_SET_ERRNO(err);
		return (*__lnb_real_system_location ()) (command);
	}

	if ( __lnb_is_forbidden_program (command, NULL, 1) != 0 )
	{
		LNB_SET_ERRNO_PERM();
		return -1;
	}
	return (*__lnb_real_system_location ()) (command);
}
