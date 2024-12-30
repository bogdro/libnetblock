/*
 * LibNetBlock - A library which blocks programs from accessing the network.
 *	-- unit test for packet capture functions.
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

#ifdef HAVE_PCAP_H
# include <pcap.h>
#else
# ifdef HAVE_PCAP_PCAP_H
#  include <pcap/pcap.h>
# endif
#endif

/* ====================== Packet capture functions */

#if (defined HAVE_PCAP_H) || (defined HAVE_PCAP_PCAP_H)
static char buf[5000];

START_TEST(test_pcap_create)
{
	pcap_t * ret;

	LNB_PROLOG_FOR_TEST();
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

	LNB_PROLOG_FOR_TEST();
	ret = pcap_open_live ("eth0", 100, 0, 1000, buf);
	if (ret != NULL)
	{
		pcap_close(ret);
		fail("test_pcap_open_live: capture opened, but shouldn't have been\n");
	}
}
END_TEST
#endif /* (defined HAVE_PCAP_H) || (defined HAVE_PCAP_PCAP_H) */


/* ========================================================== */

static Suite * lnb_create_suite(void)
{
	Suite * s = suite_create("libnetblock_pcap");

#if (defined HAVE_PCAP_H) || (defined HAVE_PCAP_PCAP_H)
	TCase * tests_pcap = tcase_create("pcap");
#endif

/* ====================== Packet capture functions */

#if (defined HAVE_PCAP_H) || (defined HAVE_PCAP_PCAP_H)
	tcase_add_test(tests_pcap, test_pcap_create);
	tcase_add_test(tests_pcap, test_pcap_open_live);
#endif

/* ====================== */

	/* set 30-second timeouts */
#if (defined HAVE_PCAP_H) || (defined HAVE_PCAP_PCAP_H)
	tcase_set_timeout(tests_pcap, 30);
#endif

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
