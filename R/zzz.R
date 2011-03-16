.onLoad <- function(libname, pkgname) {
    require("methods", quietly=TRUE)
}

.onUnload <- function( libpath ) {
  library.dynam.unload("ROAuth", libpath )
}

OAuthFactory <- getRefClass("OAuth")
OAuthFactory$accessors(names(OAuthFactory$fields()))
