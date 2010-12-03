AC_PREREQ(2.59)
AC_INIT([libsmack],[1.0])
AM_INIT_AUTOMAKE(-Wall -Werror)

AC_CONFIG_MACRO_DIR([m4])

AC_PROG_CC
AM_PROG_CC_C_O
AC_PROG_CXX
AC_PROG_INSTALL
AC_PROG_LIBTOOL
AC_PROG_MAKE_SET

# Doxygen
AC_CHECK_PROG([DOXYGEN], [doxygen], [doxygen], [])
AC_MSG_CHECKING([wheter to add documentation targets])
if test ! -z "$DOXYGEN"; then
	AC_MSG_RESULT([yes])
else
	AC_MSG_RESULT([no])
fi
AM_CONDITIONAL([HAVE_DOXYGEN],[test ! -z "$DOXYGEN"])
AC_SUBST([DOXYGEN], [$DOXYGEN])

AC_CHECK_HEADER([attr/xattr.h],[
	AC_CHECK_LIB([attr],[setxattr],[],[
		AC_MSG_ERROR([Cannot find setxattr in libattr])])
	AC_CHECK_LIB([attr],[getxattr],[],[
		AC_MSG_ERROR([Cannot find getxattr in libattr])])
],[
	AC_MSG_ERROR([Cannot find libattr header attr/xattr.h])
])

AC_CHECK_HEADERS([utarray.h  uthash.h  utlist.h  utstring.h],,
	[AC_MSG_ERROR(Cannot find uthash headers)])
PKG_CHECK_MODULES([CHECK], [check >= 0.9.4])

AC_CONFIG_FILES([Makefile src/Makefile tests/Makefile doc/Makefile libsmack.spec])

AC_OUTPUT
