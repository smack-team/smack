ACLOCAL_AMFLAGS = -I m4
AM_MAKEFLAGS = --no-print-directory

AM_CFLAGS = -Wall -Wextra

EXTRA_DIST = libsmack.sym

lib_LTLIBRARIES = libsmack.la

libsmack_la_LDFLAGS = \
	-version-info 1:0:0 \
	-Wl,--version-script=$(top_srcdir)/libsmack/libsmack.sym
libsmack_la_SOURCES = libsmack.c init.c

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = libsmack.pc

library_includedir=$(includedir)/sys
library_include_HEADERS=sys/smack.h

