AM_CPPFLAGS = -I../src

bin_PROGRAMS = printload access smackctl

printload_SOURCES = printload.c
printload_LDADD = -L$(top_builddir)/src/.libs -lsmack

access_SOURCES = access.c
access_LDADD = -L$(top_builddir)/src/.libs -lsmack

smackctl_SOURCES = smackctl.c
smackctl_LDADD = -L$(top_builddir)/src/.libs -lsmack

