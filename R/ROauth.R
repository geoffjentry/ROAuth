setRefClass("OAuth",
            fields = list(
              consumerKey = "character",
              consumerSecret = "character",
              oauthKey = "character",
              oauthSecret = "character",
              needsVerifier = "logical",
              handshakeComplete = "logical",
              verifier = "character",
              requestURL = "character",
              authURL = "character",
              accessURL = "character"
              ),
            methods = list(
              initialize = function(needsVerifier, ...) {
                if (!missing(needsVerifier))
                  needsVerifier <<- needsVerifier
                else
                  needsVerifier <<- FALSE
                handshakeComplete <<- FALSE
                callSuper(...)
              },
              isVerified = function() {
                if (needsVerifier)
                  length(verifier) != 0
                else
                  TRUE
              }, 
              requestToken = function() {
                ## FIXME:  Lock this if handshake complete
                ##   allow override to start over

                resp <- oauthPOST(requestURL,
                                  consumerKey,
                                  consumerSecret,
                                  NULL, NULL)
                vals <- parseResponse(resp)
                oauthKey <<- vals['oauth_token']
                oauthSecret <<- vals['oauth_token_secret']

                if (needsVerifier) {
                  cat(paste("To enable the connection, please direct your",
                            " web browser to: \n",
                            authURL, "?oauth_token=",
                            oauthKey,
                            "\nWhen complete, record the PIN given ",
                            "to you and call the verify() method\n",
                            "with this value as its argument.\n",
                            sep=''))
                }
              },
              verify = function(val) {
                verifier <<- val
              },
              accessToken = function() {
                if (! .self$isVerified())
                  stop("This OAuth instance has not been verified")
                resp <- oauthPOST(accessURL,
                                  consumerKey,
                                  consumerSecret,
                                  oauthKey, oauthSecret)
                vals <- parseResponse(resp)
                oauthKey <<- vals['oauth_token']
                oauthSecret <<- vals['oauth_token_secret']
                handshakeComplete <<- TRUE
              },
              OAuthRequest = function(URL) {
                if (! handshakeComplete)
                  stop("This OAuth instance has not been verified")
                oauthPOST(URLencode(URL), consumerKey, consumerSecret,
                                    oauthKey, oauthSecret)
              }
              )
            )


oauthPOST <- function(url, consumerKey, consumerSecret,
                          oauthKey, oauthSecret) {
  .Call("ROAuth_POST", url, consumerKey, consumerSecret,
        oauthKey, oauthSecret, PACKAGE="ROAuth")
}

parseResponse <- function(response) {
  ## FIXME: This does zero error handling
  
  ## Will return a named vector, so a response field of the
  ## form foo=blah&qwerty=asdf will have vals c(blah,asdf) and
  ## names will be c(foo, qwerty)
  pairs <- sapply(strsplit(response, '&')[[1]], strsplit, '=')
  out <- sapply(pairs, function(x) x[2])
  names(out) <- sapply(pairs, function(x) x[1])
  out
}

