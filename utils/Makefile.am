instdir = ${bindir}
inst_PROGRAMS = smackctl smackaccess smackself smackload smackcipso
AM_CPPFLAGS = \
	-I$(top_srcdir)/libsmack

smackctl_SOURCES = smackctl.c common.c
smackctl_LDADD = ../libsmack/libsmack.la

smackaccess_SOURCES = smackaccess.c
smackaccess_LDADD = ../libsmack/libsmack.la

smackself_SOURCES = smackself.c
smackself_LDADD = ../libsmack/libsmack.la

smackload_SOURCES = smackload.c common.c
smackload_LDADD = ../libsmack/libsmack.la

smackcipso_SOURCES = smackcipso.c common.c
smackcipso_LDADD = ../libsmack/libsmack.la
