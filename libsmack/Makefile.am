ACLOCAL_AMFLAGS = -I m4
AM_MAKEFLAGS = --no-print-directory

AM_CFLAGS = -Wall -Wextra

EXTRA_DIST = libsmack.sym

lib_LTLIBRARIES = libsmack.la

libsmack_la_LDFLAGS = \
	-version-info 3:0:2 \
	-Wl,--version-script=$(top_srcdir)/libsmack/libsmack.sym
libsmack_la_SOURCES = libsmack.c init.c
libsmack_la_LIBADD = libsmackcommon.la

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = libsmack.pc

library_includedir=$(includedir)/sys
library_include_HEADERS=sys/smack.h

noinst_LTLIBRARIES = libsmackcommon.la
libsmackcommon_la_SOURCES = common.h common.c
