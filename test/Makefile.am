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
LNBTEST_COMMON_SRC = lnbtest_common.c lnbtest_common.h
LNBTEST_COMMON_CFLAGS = @CHECK_CFLAGS@ -DHAVE_CONFIG_H -I $(top_builddir)/src
LNBTEST_COMMON_LIB = $(top_builddir)/src/libnetblock.la @CHECK_LIBS@ @LIBS@

lnbtest_banning_SOURCES = lnbtest_banning.c $(LNBTEST_COMMON_SRC)
lnbtest_banning_CFLAGS = $(LNBTEST_COMMON_CFLAGS)
lnbtest_banning_LDADD = $(LNBTEST_COMMON_LIB)

lnbtest_exec_SOURCES = lnbtest_exec.c $(LNBTEST_COMMON_SRC)
lnbtest_exec_CFLAGS = $(LNBTEST_COMMON_CFLAGS)
lnbtest_exec_LDADD = $(LNBTEST_COMMON_LIB)

lnbtest_net_SOURCES = lnbtest_net.c $(LNBTEST_COMMON_SRC)
lnbtest_net_CFLAGS = $(LNBTEST_COMMON_CFLAGS)
lnbtest_net_LDADD = $(LNBTEST_COMMON_LIB)

lnbtest_opens_SOURCES = lnbtest_opens.c $(LNBTEST_COMMON_SRC)
lnbtest_opens_CFLAGS = $(LNBTEST_COMMON_CFLAGS)
lnbtest_opens_LDADD = $(LNBTEST_COMMON_LIB)

lnbtest_pcap_SOURCES = lnbtest_pcap.c $(LNBTEST_COMMON_SRC)
lnbtest_pcap_CFLAGS = $(LNBTEST_COMMON_CFLAGS)
lnbtest_pcap_LDADD = $(LNBTEST_COMMON_LIB)

lnbtest_other_SOURCES = lnbtest_other.c $(LNBTEST_COMMON_SRC)
lnbtest_other_CFLAGS = $(LNBTEST_COMMON_CFLAGS)
lnbtest_other_LDADD = $(LNBTEST_COMMON_LIB)

x-compile: $(TESTS)
.PHONY: x-compile

endif
