AC_INIT([opc-client], [0])
AC_CONFIG_AUX_DIR([build-aux])
AC_CONFIG_MACRO_DIR([m4])
AM_INIT_AUTOMAKE([1.6 foreign dist-bzip2 subdir-objects])

AC_LANG([C++])
AC_PROG_CXX

dnl 2.0.1 is needed for evbuffers
PKG_CHECK_MODULES([LIBEVENT], [libevent >= 2.0.1])
PKG_CHECK_MODULES([LIBMODBUS], [libmodbus])
PKG_CHECK_MODULES([NCURSES], [ncurses])

LT_INIT([disable-static])

AC_CONFIG_HEADER([config.h])
AC_CONFIG_FILES([Makefile])
AC_OUTPUT
