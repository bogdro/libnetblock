/*
 * LibNetBlock - A library which blocks programs from accessing the network.
 *	-- other unit tests.
 *
 * Copyright (C) 2015-2024 Bogdan Drozdowski, bogdro (at) users . sourceforge . net
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

#include "lnbtest_common.h"

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

#include "lnb_priv.h"

/* ======================================================= */

START_TEST(test_symb_func)
{
	void * ptr;

	LNB_PROLOG_FOR_TEST();
	ptr = dlsym (RTLD_NEXT, "generic_fopen");
	if (ptr != NULL)
	{
		fail("test_symb_func: symbol found\n");
	}
}
END_TEST

/* ======================================================= */

START_TEST(test_symb_var)
{
	void * ptr;

	LNB_PROLOG_FOR_TEST();
	ptr = dlsym (RTLD_NEXT, "__lnb_allowed_socket_types");
	if (ptr != NULL)
	{
		fail("test_symb_var: symbol found\n");
	}
}
END_TEST

/* ======================================================= */

static Suite * lnb_create_suite(void)
{
	Suite * s = suite_create("libnetblock_other");

	TCase * tests_other = tcase_create("other");

	tcase_add_test(tests_other, test_symb_func);
	tcase_add_test(tests_other, test_symb_var);

	/* set 30-second timeouts */
	tcase_set_timeout(tests_other, 30);

	suite_add_tcase(s, tests_other);

	return s;
}

int main(void)
{
	int failed;

	Suite * s = lnb_create_suite();
	SRunner * sr = srunner_create(s);

	srunner_run_all(sr, CK_NORMAL);

	failed = srunner_ntests_failed(sr);
	srunner_free(sr);

	return failed;
}
