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
