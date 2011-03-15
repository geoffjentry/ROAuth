\name{OAuth-class}
\Rdversion{1.1}
\docType{class}
\alias{OAuth-class}

\title{Class "OAuth": A class to manage OAuth authentication}
\description{
  Class \code{OAuth} wraps and handles OAuth handshakes and signatures
  for the user within R
}
\section{Fields}{
  \describe{
    \item{\code{consumerKey}:}{Object of class \code{character} ~~ }
    \item{\code{consumerSecret}:}{Object of class \code{character} ~~ }
    \item{\code{oauthKey}:}{Object of class \code{character} ~~ }
    \item{\code{oauthSecret}:}{Object of class \code{character} ~~ }
    \item{\code{needsVerifier}:}{Object of class \code{logical} ~~ }
    \item{\code{handshakeComplete}:}{Object of class \code{logical} ~~ }
    \item{\code{verifier}:}{Object of class \code{character} ~~ }
    \item{\code{requestURL}:}{Object of class \code{character} ~~ }
    \item{\code{authURL}:}{Object of class \code{character} ~~ }
    \item{\code{accessURL}:}{Object of class \code{character} ~~ }
  }
}
\section{Methods}{
  \describe{
    \item{\code{isVerified()}:}{ ~~ }
    \item{\code{initialize(needsVerifier, ...)}:}{ ~~ }
    \item{\code{OAuthRequest(URL)}:}{ ~~ }
    \item{\code{handshake()}:}{ ~~ }
  }
}
\section{Extends}{
All reference classes extend and inherit methods from \code{"\linkS4class{envRefClass}"}.
}
\references{
liboauth: http://liboauth.sourceforge.net/
}
\author{
Jeff Gentry
}
\examples{
   ## This example uses a test case from liboauth and the
   ## keys are already pre-signed.  This is an example of
   ## one of the few times \code{needsVerifier} would be \code{FALSE}.
    
   reqURL <- "http://term.ie/oauth/example/request_token.php"
   cKey <- "key"
   cSecret <- "secret"
   testURL <- "http://term.ie/oauth/example/echo_api.php?method=foo%20bar"

   credentials <- OAuthFactory$new(consumerKey=cKey,
                                   consumerSecret=cSecret,
                                   requestURL=reqURL,
                                   needsVerifier=FALSE)
   credentials$handshake()
   credentials$OAuthRequest(testURL)
}
\keyword{classes}
