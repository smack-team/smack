instdir = ${bindir}
inst_PROGRAMS = smackctl smackaccess smackself
AM_CPPFLAGS = \
	-I$(top_srcdir)/libsmack

smackctl_SOURCES = smackctl.c
smackctl_LDADD = ../libsmack/libsmack.la

smackaccess_SOURCES = smackaccess.c
smackaccess_LDADD = ../libsmack/libsmack.la

smackself_SOURCES = smackself.c
smackself_LDADD = ../libsmack/libsmack.la
