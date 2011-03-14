AC_INIT([ROAuth], 1.x, [geoffjentry@gmail.com], [ROAuth])

AC_CHECK_LIB([oauth], [oauth_http_post],,[AC_MSG_ERROR([need liboauth with oauth_http_post])])

AC_CHECK_HEADERS([oauth.h])

AC_OUTPUT(src/Makevars)
