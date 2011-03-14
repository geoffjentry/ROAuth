#include <R.h>
#include <Rdefines.h>
#include <R_ext/Rdynload.h>
#include <stdlib.h>
#include <oauth.h>

#define STR(SE) CHAR(STRING_ELT(SE,0))

SEXP ROAuth_POST(SEXP, SEXP, SEXP, SEXP, SEXP);
SEXP ROAuth_GET(char *, char *, char *, char *, char *);
