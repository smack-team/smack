AM_CPPFLAGS = -I../src

bin_PROGRAMS = smackctl smackaccess

smackctl_SOURCES = smackctl.c
smackctl_LDADD = -L$(top_builddir)/src/.libs -lsmack

smackaccess_SOURCES = smackaccess.c
smackaccess_LDADD = -L$(top_builddir)/src/.libs -lsmack
