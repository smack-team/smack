instdir = ${bindir}
bin_PROGRAMS = smackaccess smackload smackcipso chsmack smackctl
AM_CPPFLAGS = -I$(top_srcdir)/libsmack

smackaccess_SOURCES = smackaccess.c
smackaccess_LDADD = ../libsmack/libsmack.la ../libsmack/libsmackcommon.la

smackload_SOURCES = smackload.c
smackload_LDADD = ../libsmack/libsmack.la ../libsmack/libsmackcommon.la

smackcipso_SOURCES = smackcipso.c
smackcipso_LDADD = ../libsmack/libsmack.la ../libsmack/libsmackcommon.la

smackctl_SOURCES = smackctl.c
smackctl_LDADD = ../libsmack/libsmack.la ../libsmack/libsmackcommon.la

chsmack_SOURCES = chsmack.c
chsmack_LDADD = ../libsmack/libsmack.la ../libsmack/libsmackcommon.la
