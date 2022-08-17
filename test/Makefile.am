if LNB_TESTS_ENABLED

TESTS = lnbtest
check_PROGRAMS = lnbtest
lnbtest_SOURCES = lnbtest.c
lnbtest_CFLAGS = @CHECK_CFLAGS@ -I $(top_builddir)/src
lnbtest_LDADD = $(top_builddir)/src/libnetblock.la @CHECK_LIBS@ @LIBS@

endif
