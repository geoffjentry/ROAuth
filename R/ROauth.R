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
              accessURL = "character",
              curlHandle = "CURLHandle"              
              ),
            methods = list(
              initialize = function(needsVerifier, ...) {
                if (!missing(needsVerifier))
                  needsVerifier <<- needsVerifier
                else
                  needsVerifier <<- TRUE
                handshakeComplete <<- FALSE
                if(!("curlHandle" %in% names(list(...))))
                  curlHandle <<- getCurlHandle()                
                callSuper(...)
              },
              
              handshake = function(..., curl = curlHandle) {
                ' Performs the OAuth handshake.  In most cases
                  the user will need to complete a manual step
                  with their web browser, entering a PIN into
                  this function.
                '
                handshakeComplete <<- FALSE
                resp <- oauthPOST(requestURL, , 
                                  consumerKey,
                                  consumerSecret,
                                  NULL, NULL, curl = curl, ...)
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

                resp <- oauthPOST(accessURL, ,
                                  consumerKey,
                                  consumerSecret,
                                  oauthKey, oauthSecret, curl = curl, ...)
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
              
              OAuthRequest = function(URL, params, method="GET",
                                      customHeader=NULL,
                                      curl = curlHandle, ...) {
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

                httpFunc(URLencode(URL), params, consumerKey = consumerKey,
                         consumerSecret = consumerSecret,
                         oauthKey = oauthKey, oauthSecret = oauthSecret,
                         customHeader = customHeader, curl = curl, ...)
              }
              )
            )

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

oauthPOST <- function(url, params = character(), consumerKey, consumerSecret,
                      oauthKey, oauthSecret, customHeader = NULL,
                      curl = getCurlHandle(), ...) {
  if(is.null(curl))
    curl <- getCurlHandle()
  
  auth <- signRequest(url, params, consumerKey, consumerSecret,
                      oauthKey=oauthKey, oauthSecretoauthSecret,
                      httpMethod="POST")
  opts <- list(...)
  
  ## post ,specify the method
  ## We should be able to use postForm() but we have to work out the issues
  ## with escaping, etc. to match the signature mechanism.
  if(TRUE) {   
    reader <- dynCurlReader(curl, baseURL = url, verbose = FALSE)
    fields <- paste(names(auth), sapply(auth, curlPercentEncode),
                    sep = "=", collapse = "&")
    curlPerform(curl = curl, URL = url, postfields = fields,
                writefunction = reader$update, ...)
    reader$value()
  } else
  postForm(url, .params = c(params, lapply(auth, I)), curl = curl,
           .opts = opts, style = "POST")
}

#XXX? use .opts for the curl options.
#     add a ... for the parameters.

oauthGET <- function(url, params = character(), consumerKey, consumerSecret,
                     oauthKey, oauthSecret, customHeader = NULL,
                     curl = getCurlHandle(), ..., .opts = list(...)) {
  ##   opts = list(httpheader = c(Authentication = paste(names(auth),  auth, sep = "=", collapse = "\n   ")), ...)
  if(is.null(curl))
    curl <- getCurlHandle()
   
   auth <- signRequest(url, params, consumerKey, consumerSecret,
                       oauthKey=oauthKey, oauthSecret=oauthSecret,
                       httpMethod="GET")

   params <- c(params, as.list(auth))
   getForm(url, .params = params, curl = curl,
           .opts = c(httpget = TRUE,  list(...)))
}
