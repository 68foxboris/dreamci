AC_INIT([dreamci],[9.7],[dreamci@dreamcidevelopers.com])
AM_INIT_AUTOMAKE([foreign])

AC_CONFIG_SRCDIR([src/main.c])

m4_ifdef([AM_SILENT_RULES], [AM_SILENT_RULES([yes])])
AC_USE_SYSTEM_EXTENSIONS
AC_SYS_LARGEFILE

dnl find a compiler
AC_PROG_CC
AC_PROG_CC_STDC

dnl check if the compiler supports '-c' and '-o' options
AM_PROG_CC_C_O

# Checks for header files.
AC_CHECK_HEADERS([stdio.h stdlib.h fcntl.h string.h getopt.h byteswap.h netinet/in.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_TYPE_SIZE_T

AC_CONFIG_FILES([
Makefile
src/Makefile
])
AC_OUTPUT
