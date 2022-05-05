
pam_moduledir = $(SECUREDIR)
pam_module_LTLIBRARIES = 
man_MANS =
if PAM
  pam_module_LTLIBRARIES += pam_smack.la
  man_MANS += pam_smack.8
endif
AM_LDFLAGS = -no-undefined -avoid-version -module
AM_CPPFLAGS = -I$(top_srcdir)/libsmack
pam_smack_la_SOURCES = pam_smack.c
pam_smack_la_LIBADD = -lpam $(top_srcdir)/libsmack/libsmack.la $(top_srcdir)/libsmack/libsmackcommon.la
EXTRA_DIST = $(man_MANS)
