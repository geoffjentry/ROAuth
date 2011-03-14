.First.lib <- function(libname, pkgname)
  library.dynam('ROAuth', package='ROAuth')

.onLoad <- .First.lib
