setRefClass("OAuth",
            fields = list(
              consumerKey = "character",
              consumerSecret = "character",
              oauthKey = "character",
              oauthSecret = "character",
              hasVerifier = "logical",
              verifier = "character",
              requestURL = "character",
              authURL = "character",
              accessURL = "character"
              ),
            methods = list(
              requestToken = function() {
                resp <- oauthPOST(requestURL,
                                  consumerKey,
                                  consumerSecret,
                                  NULL, NULL)
                vals <- parseResponse(resp)
                oauthKey <<- vals['oauth_token']
                oauthSecret <<- vals['oauth_token_secret']
              },
              accessToken = function() {
                if ((hasVerifier) && (length(verifier) == 0))
                  stop("This OAuth instances has not been verified")
                resp <- oauthPOST(accessURL,
                                  consumerKey,
                                  consumerSecret,
                                  oauthKey, oauthSecret)
                vals <- parseResponse(resp)
                oauthKey <<- vals['oauth_token']
                oauthSecret <<- vals['oauth_token_secret']
              },
              authorize = function() {
                resp <- oauthPOST(accessURL,
                                  consumerKey,
                                  consumerSecret,
                                  oauthKey, oauthSecret)
                vals <- parseResponse(resp)
                ## FIXME:  PIN?
                print("Need PIN, dude")
              },
              OAuthRequest = function(URL, args) {
                if ((hasVerifier) && (length(verifier) == 0))
                  stop("This OAuth instances has not been verified")
                ## FIXME: Build up URL & send
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
  ## names iwll be c(foo, qwerty)
  pairs <- sapply(strsplit(response, '&')[[1]], strsplit, '=')
  out <- sapply(pairs, function(x) x[2])
  names(out) <- sapply(pairs, function(x) x[1])
  out
}

