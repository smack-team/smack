AC_PREREQ(2.60)
AC_INIT([libsmack],
	[1.0],
	[jarkko.sakkinen@intel.com],
	[libsmack],
	[https://github.com/organizations/smack-team/smack])
AC_CONFIG_SRCDIR([libsmack/libsmack.c])
AC_CONFIG_AUX_DIR([build-aux])
AM_INIT_AUTOMAKE([-Wall -Werror dist-bzip2 foreign])
AC_USE_SYSTEM_EXTENSIONS
AC_CONFIG_MACRO_DIR([m4])
AM_SILENT_RULES([yes])
LT_INIT([disable-static])
AC_PREFIX_DEFAULT([/usr])

AC_CHECK_PROG([DOXYGEN], [doxygen], [doxygen], [])
AC_MSG_CHECKING([for doxygen])
if test ! -z "$DOXYGEN"; then
	AC_MSG_RESULT([yes])
else
	AC_MSG_RESULT([no])
fi
AM_CONDITIONAL([ENABLE_DOXYGEN],[test ! -z "$DOXYGEN"], [Build API documentation.])
AC_SUBST([DOXYGEN], [$DOXYGEN])

# systemd
AC_ARG_WITH([systemdsystemunitdir],
        AS_HELP_STRING([--with-systemdsystemunitdir=DIR], [Directory for systemd service files]),
        [],
        [with_systemdsystemunitdir=$(pkg-config --silence-errors --variable=systemdsystemunitdir systemd)])
AC_SUBST([systemdsystemunitdir], [$with_systemdsystemunitdir])
AM_CONDITIONAL(HAVE_SYSTEMD, [test -n "$with_systemdsystemunitdir"])

AC_CONFIG_FILES([Makefile libsmack/Makefile libsmack/libsmack.pc utils/Makefile doc/Makefile init/Makefile])

AC_OUTPUT
