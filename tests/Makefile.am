TESTS = check_rules check_xattr
check_PROGRAMS = check_rules check_xattr 

check_rules_SOURCES = check_rules.c $(top_builddir)/src/smack.h
check_rules_CFLAGS = @CHECK_CFLAGS@
check_rules_LDADD = $(top_builddir)/src/libsmack.la @CHECK_LIBS@

check_xattr_SOURCES = check_xattr.c $(top_builddir)/src/smack.h
check_xattr_CFLAGS = @CHECK_CFLAGS@
check_xattr_LDADD = $(top_builddir)/src/libsmack.la @CHECK_LIBS@
