AC_INIT([ROAuth], 1.0, [geoffjentry@gmail.com], [ROAuth])

AC_CONFIG_SRCDIR(src/ROAuth.c)

# find R home and set correct compiler + flags
: ${R_HOME=`R RHOME`}
if test -z "${R_HOME}"; then
  AC_MSG_ERROR([cannot determine R_HOME. Make sure you use R CMD INSTALL!])
fi
RBIN="${R_HOME}/bin/R"

: ${CC=`"${RBIN}" CMD config CC`}
: ${CPP=`"${RBIN}" CMD config CPP`}
: ${CFLAGS=`"${RBIN}" CMD config CFLAGS`}

# honor PKG_xx overrides
LIBS="${LIBS} ${PKG_LIBS}"
CPPFLAGS="${CPPFLAGS} ${PKG_CPPFLAGS}"

ROAuthok=yes
AC_CHECK_HEADERS(oauth.h, ROAuthok=no)
AC_CHECK_LIB(oauth, ROAuthok=no)
if test "${ROAuthok}" = no; then
   AC_MSG_ERROR([liboauth and/or oauth.h not found in standard search locations.

*** Install liboauth and if necessary set PKG_CPPFLAGS/PKG_LIBS accordingly.])
fi

AC_ARG_VAR([PKG_CPPFLAGS],[custom C preprocessor flags for packages compilation])
AC_ARG_VAR([PKG_LIBS],[custom libraries for package compilation])

AC_CONFIG_FILES(src/Makevars)
AC_OUTPUT


