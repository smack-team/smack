ACLOCAL_AMFLAGS = -I m4 ${ACLOCAL_FLAGS}
AM_MAKEFLAGS = --no-print-directory

EXTRA_DIST = libsmack/libsmack.sym

library_includedir=$(includedir)
library_include_HEADERS=libsmack/sys/smack.h

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = libsmack.pc

SUBDIRS = libsmack utils doc
