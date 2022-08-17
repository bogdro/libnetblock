lib_LTLIBRARIES = libnetblock.la
libnetblock_la_SOURCES = lnb_exec.c lnb_main.c lnb_net.c lnb_banning.c \
	lnb_opens.c lnb_priv.h lnb_pcap.c
EXTRA_DIST = lnb_cfg.h.in lnb_public.c.in libnetblock.h.in \
	randomize_names_gawk.sh randomize_names_perl.sh

# VERSION = C:R:A     (current, revision, age)
# only code changed => R++
# interface changed => C++, R:=0
# - interface add => A++
# - interface removed => A:=0
libnetblock_la_LDFLAGS = -version-info 2:2:1

#nobase_include_HEADERS = lnb_priv.h

nobase_include_HEADERS = libnetblock.h
BUILT_SOURCES = lnb_paths.h libnetblock.h
nodist_libnetblock_la_SOURCES = lnb_paths.h libnetblock.h
libnetblock_la_DISTCLEANFILES = lnb_paths.h libnetblock.h

lnb_paths.h: Makefile
	echo '#define SYSCONFDIR "$(sysconfdir)"' > lnb_paths.h

if PUBLIC_INTERFACE
nodist_libnetblock_la_SOURCES += lnb_public.c
libnetblock_la_DISTCLEANFILES += lnb_public.c
endif

