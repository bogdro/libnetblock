SUBDIRS = src doc

ACLOCAL_AMFLAGS = -I m4

EXTRA_DIST = libnetblock.spec.in doc/libnetblock.3 m4/ax_c_check_flag.m4 \
	m4/ax_gcc_warn_unused_result.m4 m4/ac_prototype.m4 m4/ac_define_path_style.m4

pack:	doc/libnetblock.info
	make dist-gzip
	mkdir -p libnetblock-@VERSION@/doc
	echo '\input texinfo'			 > libnetblock-@VERSION@/doc/libnetblock.texi
	echo '@setfilename libnetblock.info'	>> libnetblock-@VERSION@/doc/libnetblock.texi
	echo '@settitle libnetblock manual'	>> libnetblock-@VERSION@/doc/libnetblock.texi
	echo '@bye'				>> libnetblock-@VERSION@/doc/libnetblock.texi
	gunzip -f libnetblock-@VERSION@.tar.gz
	tar --delete -f libnetblock-@VERSION@.tar libnetblock-@VERSION@/doc/libnetblock.texi
	tar -rf libnetblock-@VERSION@.tar libnetblock-@VERSION@/doc/libnetblock.texi
	gzip -9 -f libnetblock-@VERSION@.tar
	rm -fr libnetblock-@VERSION@
