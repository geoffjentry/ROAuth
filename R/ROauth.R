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
                  needsVerifier <<- TRUE
                handshakeComplete <<- FALSE
                callSuper(...)
              },
              handshake = function() {
                ' Performs the OAuth handshake.  In most cases
                  the user will need to complete a manual step
                  with their web browser, entering a PIN into
                  this function.
                '
                handshakeComplete <<- FALSE
                resp <- oauthPOST(requestURL,
                                  consumerKey,
                                  consumerSecret,
                                  NULL, NULL)
                vals <- parseResponse(resp)
                if (!all(c('oauth_token', 'oauth_token_secret') %in%
                         names(vals))) {
                  stop("Invalid response from site, please ",
                     "check your consumerKey and consumerSecret",
                     " and try again.")
                }
                oauthKey <<- vals['oauth_token']
                oauthSecret <<- vals['oauth_token_secret']
                if (needsVerifier) {
                  verifyURL <- paste(authURL, "?oauth_token=",
                                     oauthKey, sep='')
                  msg <- paste("To enable the connection, please direct",
                               " your web browser to: \n",
                               verifyURL,
                               "\nWhen complete, record the PIN given ",
                               "to you and provide it here: ", sep='')
                  verifier <<- readline(prompt=msg)
                  accessURL <<- paste(accessURL,
                                      "?oauth_verifier=",
                                      verifier, sep='')
                }

                resp <- oauthPOST(accessURL,
                                  consumerKey,
                                  consumerSecret,
                                  oauthKey, oauthSecret)
                vals <- parseResponse(resp)
                if (!all(c('oauth_token', 'oauth_token_secret') %in%
                         names(vals))) {
                  stop("Invalid response after authorization.  ",
                       "You likely misentered your PIN, try rerunning",
                       " this handshake & browser authorization to get",
                       " a new PIN.")
                }
                oauthKey <<- vals['oauth_token']
                oauthSecret <<- vals['oauth_token_secret']
                handshakeComplete <<- TRUE
              },
              
              isVerified = function() {
                'Will report if this object is verified or not.
                 Verification can either involve not needing it
                 in the first place, or as part of the handshake'
                if (needsVerifier)
                  length(verifier) != 0
                else
                  TRUE
              },
              
              OAuthRequest = function(URL, method="GET", customHeader=NULL) {
                ' If the OAuth handshake has been completed, will
                submit a URL request with an OAuth signature, returning
                any response from the server
                '
                if (! handshakeComplete)
                  stop("This OAuth instance has not been verified")

                httpFunc <- switch(method,
                                   POST = oauthPOST,
                                   GET = oauthGET,
                                   stop("method must be POST or GET"))

                httpFunc(URLencode(URL), consumerKey, consumerSecret,
                         oauthKey, oauthSecret, customHeader)
              }
              )
            )


oauthPOST <- function(url, consumerKey, consumerSecret,
                      oauthKey, oauthSecret,
                      customHeader=NULL) {
  .Call("ROAuth_POST", url, consumerKey, consumerSecret,
        oauthKey, oauthSecret, customHeader, PACKAGE="ROAuth")
}

oauthGET <- function(url, consumerKey, consumerSecret,
                     oauthKey, oauthSecret,
                     customHeader=NULL) {
  .Call("ROAuth_GET", url, consumerKey, consumerSecret,
        oauthKey, oauthSecret, customHeader, PACKAGE="ROAuth")
}


parseResponse <- function(response) {
  ## Will return a named vector, so a response field of the
  ## form foo=blah&qwerty=asdf will have vals c(blah,asdf) and
  ## names will be c(foo, qwerty).  If the response is borked,
  ## the output of this function will be as well, so caveat
  ## emptor, GIGO, etc
  pairs <- sapply(strsplit(response, '&')[[1]], strsplit, '=')
  out <- sapply(pairs, function(x) x[2])
  names(out) <- sapply(pairs, function(x) x[1])
  out
}

