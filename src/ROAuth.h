#include <R.h>
#include <Rdefines.h>
#include <R_ext/Rdynload.h>
#include <stdlib.h>
#include <oauth.h>

#define STR(SE) CHAR(STRING_ELT(SE,0))

#define POST 0
#define GET 1

SEXP ROAuth_HTTP(SEXP, SEXP, SEXP, SEXP, SEXP, SEXP, int);
SEXP ROAuth_POST(SEXP, SEXP, SEXP, SEXP, SEXP, SEXP);
SEXP ROAuth_GET(SEXP, SEXP, SEXP, SEXP, SEXP, SEXP);
