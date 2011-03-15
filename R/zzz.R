.First.lib <- function(libname, pkgname)
  library.dynam('ROAuth', package='ROAuth')

.onLoad <- .First.lib

OAuthFactory <- getRefClass("OAuth")
OAuthFactory$accessors(names(OAuthFactory$fields()))
