ACLOCAL_AMFLAGS = -I m4 ${ACLOCAL_FLAGS}
AM_MAKEFLAGS = --no-print-directory

library_includedir=$(includedir)
library_include_HEADERS=libsmack/sys/smack.h

SUBDIRS = libsmack utils doc

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = libsmack.pc
