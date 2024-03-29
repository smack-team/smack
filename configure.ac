AC_PREREQ(2.60)
AC_INIT([libsmack],
	[1.3.3],
	[r.krypa@samsung.com],
	[libsmack],
	[https://github.com/smack-team/smack])

AC_CONFIG_SRCDIR([libsmack/libsmack.c])
AC_CONFIG_AUX_DIR([build-aux])
AC_CONFIG_HEADERS([utils/config.h])
AM_INIT_AUTOMAKE([-Wall -Werror dist-bzip2 foreign])
AC_GNU_SOURCE
AC_CONFIG_MACRO_DIR([m4])
AM_SILENT_RULES([yes])
m4_ifdef([AM_PROG_AR], [AM_PROG_AR])
LT_INIT([disable-static])
AC_PREFIX_DEFAULT([/usr])
AC_PROG_CC_C99

AC_CHECK_PROG([DOXYGEN], [doxygen], [doxygen], [])
AC_MSG_CHECKING([for doxygen])
if test ! -z "$DOXYGEN"; then
	AC_MSG_RESULT([yes])
else
	AC_MSG_RESULT([no])
fi
AM_CONDITIONAL([ENABLE_DOXYGEN],[test ! -z "$DOXYGEN"], [Build API documentation.])
AM_COND_IF([ENABLE_DOXYGEN], [AC_CONFIG_FILES([doc/Doxyfile])])
AC_SUBST([DOXYGEN], [$DOXYGEN])

#pam
AC_ARG_ENABLE(securedir,
	AS_HELP_STRING([--enable-securedir=DIR],[path to location of PAMs @<:@default=$libdir/security@:>@]),
	SECUREDIR=$enableval, SECUREDIR=$libdir/security)
AC_SUBST(SECUREDIR)

AC_CHECK_HEADER([security/pam_modules.h],[PAM_HEADER=yes])
AC_CHECK_LIB([pam],pam_get_user,[PAM_LIB=yes])
AM_CONDITIONAL([PAM], [test x$PAM_HEADER = xyes -a x$PAM_LIB = xyes])

# systemd
systemd_new=no
PKG_CHECK_MODULES([SYSTEMD],
                  systemd >= 198,
                  [systemd_new=yes],
                  [systemd_new=no])

AC_ARG_WITH([systemdsystemunitdir],
        AS_HELP_STRING([--with-systemdsystemunitdir=DIR], [Directory for systemd service files]),
        [],
        [with_systemdsystemunitdir=$(pkg-config --silence-errors --variable=systemdsystemunitdir systemd)])
AC_SUBST([systemdsystemunitdir], [$with_systemdsystemunitdir])
AM_CONDITIONAL(HAVE_SYSTEMD, [test -n "$with_systemdsystemunitdir"])
AM_CONDITIONAL(HAVE_SYSTEMD_NEW, [test "$systemd_new" = "yes"])

AC_CONFIG_FILES([
	Makefile
	libsmack/Makefile
	libsmack/libsmack.pc
	utils/Makefile
	doc/Makefile
	pam/Makefile
	init/Makefile])

AC_OUTPUT
