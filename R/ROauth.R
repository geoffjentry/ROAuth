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
        oauthKey, oauthSecret, PACKAGE="ROAUTH")
}
