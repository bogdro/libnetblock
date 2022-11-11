#
# LibNetBlock - A library which blocks programs from accessing the network.
#	-- Makefile.am, part of the build system.
#
# Copyright (C) 2007-2022 Bogdan Drozdowski, bogdro (at) users . sourceforge . net
# License: GNU General Public License, v3+
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 3
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#

if LNB_TESTS_ENABLED

TESTS = lnbtest_banning lnbtest_exec lnbtest_net lnbtest_opens lnbtest_pcap lnbtest_other
check_PROGRAMS = lnbtest_banning lnbtest_exec lnbtest_net lnbtest_opens lnbtest_pcap lnbtest_other

#nobase_nodist_include_HEADERS = lnbtest_common.h
#nobase_include_HEADERS = lnbtest_common.h
#nodist_include_HEADERS = lnbtest_common.h
EXTRA_DIST = lnbtest_common.h

lnbtest_banning_SOURCES = lnbtest_banning.c lnbtest_common.c lnbtest_common.h
lnbtest_banning_CFLAGS = @CHECK_CFLAGS@ -I $(top_builddir)/src
lnbtest_banning_LDADD = $(top_builddir)/src/libnetblock.la @CHECK_LIBS@ @LIBS@

lnbtest_exec_SOURCES = lnbtest_exec.c lnbtest_common.c lnbtest_common.h
lnbtest_exec_CFLAGS = @CHECK_CFLAGS@ -I $(top_builddir)/src
lnbtest_exec_LDADD = $(top_builddir)/src/libnetblock.la @CHECK_LIBS@ @LIBS@

lnbtest_net_SOURCES = lnbtest_net.c lnbtest_common.c lnbtest_common.h
lnbtest_net_CFLAGS = @CHECK_CFLAGS@ -I $(top_builddir)/src
lnbtest_net_LDADD = $(top_builddir)/src/libnetblock.la @CHECK_LIBS@ @LIBS@

lnbtest_opens_SOURCES = lnbtest_opens.c lnbtest_common.c lnbtest_common.h
lnbtest_opens_CFLAGS = @CHECK_CFLAGS@ -I $(top_builddir)/src
lnbtest_opens_LDADD = $(top_builddir)/src/libnetblock.la @CHECK_LIBS@ @LIBS@

lnbtest_pcap_SOURCES = lnbtest_pcap.c lnbtest_common.c lnbtest_common.h
lnbtest_pcap_CFLAGS = @CHECK_CFLAGS@ -I $(top_builddir)/src
lnbtest_pcap_LDADD = $(top_builddir)/src/libnetblock.la @CHECK_LIBS@ @LIBS@

lnbtest_other_SOURCES = lnbtest_other.c lnbtest_common.c lnbtest_common.h
lnbtest_other_CFLAGS = @CHECK_CFLAGS@ -I $(top_builddir)/src
lnbtest_other_LDADD = $(top_builddir)/src/libnetblock.la @CHECK_LIBS@ @LIBS@

zcompile: $(TESTS)
.PHONY: zcompile

endif
