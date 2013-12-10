instdir = ${bindir}
bin_PROGRAMS = smackaccess smackload smackcipso chsmack smackctl
AM_CPPFLAGS = -I$(top_srcdir)/libsmack

smackaccess_SOURCES = smackaccess.c
smackaccess_LDADD = ../libsmack/libsmack.la

smackload_SOURCES = smackload.c common.c
smackload_LDADD = ../libsmack/libsmack.la

smackcipso_SOURCES = smackcipso.c common.c
smackcipso_LDADD = ../libsmack/libsmack.la

smackctl_SOURCES = smackctl.c common.c
smackctl_LDADD = ../libsmack/libsmack.la

chsmack_SOURCES = chsmack.c
chsmack_LDADD = ../libsmack/libsmack.la

EXTRA_DIST = common.h
