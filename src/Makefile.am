ACLOCAL_AMFLAGS = -I m4
AM_MAKEFLAGS = --no-print-directory

lib_LTLIBRARIES = libsmack.la

libsmack_la_LDFLAGS = \
	-version-info 1:0:0 \
	-Wl,--version-script=$(top_srcdir)/src/libsmack.sym
libsmack_la_SOURCES = libsmack.c

