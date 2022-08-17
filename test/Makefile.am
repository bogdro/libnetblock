if LNB_TESTS_ENABLED

TESTS = lnbtest_banning lnbtest_exec lnbtest_net lnbtest_opens lnbtest_pcap
check_PROGRAMS = lnbtest_banning lnbtest_exec lnbtest_net lnbtest_opens lnbtest_pcap

#nobase_nodist_include_HEADERS = lnbtest_common.h
#nobase_include_HEADERS = lnbtest_common.h
#nodist_include_HEADERS = lnbtest_common.h
EXTRA_DIST = lnbtest_common.h

lnbtest_banning_SOURCES = lnbtest_banning.c lnbtest_common.h
lnbtest_banning_CFLAGS = @CHECK_CFLAGS@ -I $(top_builddir)/src
lnbtest_banning_LDADD = $(top_builddir)/src/libnetblock.la @CHECK_LIBS@ @LIBS@

lnbtest_exec_SOURCES = lnbtest_exec.c lnbtest_common.h
lnbtest_exec_CFLAGS = @CHECK_CFLAGS@ -I $(top_builddir)/src
lnbtest_exec_LDADD = $(top_builddir)/src/libnetblock.la @CHECK_LIBS@ @LIBS@

lnbtest_net_SOURCES = lnbtest_net.c lnbtest_common.h
lnbtest_net_CFLAGS = @CHECK_CFLAGS@ -I $(top_builddir)/src
lnbtest_net_LDADD = $(top_builddir)/src/libnetblock.la @CHECK_LIBS@ @LIBS@

lnbtest_opens_SOURCES = lnbtest_opens.c lnbtest_common.h
lnbtest_opens_CFLAGS = @CHECK_CFLAGS@ -I $(top_builddir)/src
lnbtest_opens_LDADD = $(top_builddir)/src/libnetblock.la @CHECK_LIBS@ @LIBS@

lnbtest_pcap_SOURCES = lnbtest_pcap.c lnbtest_common.h
lnbtest_pcap_CFLAGS = @CHECK_CFLAGS@ -I $(top_builddir)/src
lnbtest_pcap_LDADD = $(top_builddir)/src/libnetblock.la @CHECK_LIBS@ @LIBS@

endif
