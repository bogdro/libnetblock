#
# LibNetBlock - A library which blocks programs from accessing the network.
#	-- Makefile.am, part of the build system.
#
# Copyright (C) 2007-2024 Bogdan Drozdowski, bogdro (at) users . sourceforge . net
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

lib_LTLIBRARIES = libnetblock.la
libnetblock_la_SOURCES = lnb_exec.c lnb_main.c lnb_net.c lnb_banning.c \
	lnb_opens.c lnb_priv.h lnb_pcap.c
EXTRA_DIST = lnb_cfg.h.in lnb_public.c.in libnetblock.h.in \
	randomize_names_gawk.sh randomize_names_perl.sh banning-generic.c

# VERSION = C:R:A     (current, revision, age)
# only code changed => R++
# interface changed => C++, R:=0
# - interface add => A++
# - interface removed => A:=0
libnetblock_la_LDFLAGS = -version-info 5:0:0

#nobase_include_HEADERS = lnb_priv.h

nobase_nodist_include_HEADERS = libnetblock.h
BUILT_SOURCES = lnb_paths.h libnetblock.h
nodist_libnetblock_la_SOURCES = lnb_paths.h libnetblock.h
libnetblock_la_DISTCLEANFILES = lnb_paths.h libnetblock.h

lnb_paths.h: Makefile
	echo '#define SYSCONFDIR "$(sysconfdir)"' > lnb_paths.h

if PUBLIC_INTERFACE
nodist_libnetblock_la_SOURCES += lnb_public.c
libnetblock_la_DISTCLEANFILES += lnb_public.c
endif

x-randomnames: clean
	./randomize_names_gawk.sh

.PHONY: x-randomnames
