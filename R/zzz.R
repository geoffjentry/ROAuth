.onLoad <- function(libname, pkgname) {
    require("methods", quietly=TRUE)
}

.onUnload <- function( libpath ) {
  library.dynam.unload("OAuthInR", libpath )
}

OAuthFactory <- getRefClass("OAuth")
OAuthFactory$accessors(names(OAuthFactory$fields()))
