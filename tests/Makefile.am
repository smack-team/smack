AM_CPPFLAGS = -I../src

noinst_PROGRAMS = smackctl smackaccess smackself

smackctl_SOURCES = smackctl.c
smackctl_LDADD = -L$(top_builddir)/src/.libs -lsmack

smackaccess_SOURCES = smackaccess.c
smackaccess_LDADD = -L$(top_builddir)/src/.libs -lsmack

smackself_SOURCES = smackself.c
smackself_LDADD = -L$(top_builddir)/src/.libs -lsmack
