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

SUBDIRS = src doc test

ACLOCAL_AMFLAGS = -I m4

EXTRA_DIST = libnetblock.spec.in doc/libnetblock.3 m4/ax_c_check_flag.m4 \
	m4/ax_gcc_warn_unused_result.m4 m4/ac_prototype.m4 m4/ac_define_path_style.m4 \
	m4/ax_check_link_flag.m4

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = libnetblock.pc

pack:	doc/libnetblock.info dist-gzip
	tar zxf libnetblock-@VERSION@.tar.gz
	echo '\input texinfo'			 > libnetblock-@VERSION@/doc/libnetblock.texi
	echo '@setfilename libnetblock.info'	>> libnetblock-@VERSION@/doc/libnetblock.texi
	echo '@settitle libnetblock manual'	>> libnetblock-@VERSION@/doc/libnetblock.texi
	echo '@bye'				>> libnetblock-@VERSION@/doc/libnetblock.texi
	tar zcf libnetblock-@VERSION@.tar.gz libnetblock-@VERSION@
	rm -fr libnetblock-@VERSION@

.PHONY: pack
