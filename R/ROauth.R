setRefClass("OAuth",
            fields = list(
              consumerKey = "character",
              consumerSecret = "character",
              oauthKey = "character",
              oauthSecret = "character",
              verifier = "character",
              requestURL = "character",
              authURL = "character",
              accessURL = "character"
              ),
            methods = list(
              )
            )


oauthPOST <- function(url, consumerKey, consumerSecret,
                          oauthKey, oauthSecret) {
  ## FIXME:  This should be a method of the class
  .Call("ROAuth_POST", url, consumerKey, consumerSecret,
        oauthKey, oauthSecret, PACKAGE="ROAuth")
}

parseResponse <- function(response) {
  ## Will return a named vector, so a response field of the
  ## form foo=blah&qwerty=asdf will have vals c(blah,asdf) and
  ## names iwll be c(foo, qwerty)
  pairs <- sapply(strsplit(response, '&')[[1]], strsplit, '=')
  out <- sapply(pairs, function(x) x[2])
  names(out) <- sapply(pairs, function(x) x[1])
  out
}

