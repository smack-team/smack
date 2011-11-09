ACLOCAL_AMFLAGS = -I m4 ${ACLOCAL_FLAGS}
AM_MAKEFLAGS = --no-print-directory

library_includedir=$(includedir)
library_include_HEADERS=src/libsmack.h

SUBDIRS = src tests doc

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = libsmack.pc
