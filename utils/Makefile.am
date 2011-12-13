instdir = ${bindir}
bin_PROGRAMS = smackctl smackaccess smackload smackcipso smackd chsmack
AM_CPPFLAGS = \
	-I$(top_srcdir)/libsmack

smackctl_SOURCES = smackctl.c common.c
smackctl_LDADD = ../libsmack/libsmack.la

smackaccess_SOURCES = smackaccess.c
smackaccess_LDADD = ../libsmack/libsmack.la

smackload_SOURCES = smackload.c common.c
smackload_LDADD = ../libsmack/libsmack.la

smackcipso_SOURCES = smackcipso.c common.c
smackcipso_LDADD = ../libsmack/libsmack.la

smackd_SOURCES = smackd.c common.c
smackd_LDADD = ../libsmack/libsmack.la

chsmack_SOURCES = chsmack.c

EXTRA_DIST = common.h
