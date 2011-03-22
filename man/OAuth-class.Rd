\name{OAuth-class}
\Rdversion{1.1}
\docType{class}
\alias{OAuth-class}
\alias{ROAuth}
\alias{OAuth}
\alias{OAuthFactory}
\title{Class "OAuth": A class to manage OAuth authentication}
\description{
  Class \code{OAuth} wraps and handles OAuth handshakes and signatures
  for the user within R
}
\section{Fields}{
  \describe{
    \item{\code{consumerKey}:}{The consumer key provided by your application}
    \item{\code{consumerSecret}:}{The consumer secret provided by your
      application}
    \item{\code{needsVerifier}:}{Whether or not this \code{OAuth} needs
      the verification step.  Defaults to \code{TRUE}}
    \item{\code{handshakeComplete}:}{Whether or not the handshaking was
      successfully completed}
    \item{\code{requestURL}:}{The URL provided for retrieving request tokens}
    \item{\code{authURL}:}{The URL provided for
      authorization/verification purposes}
    \item{\code{accessURL}:}{The URL provided for retrieving access tokens}
    \item{\code{oauthKey}:}{For internal use}
    \item{\code{oauthSecret}:}{For internal use}
    \item{\code{verifier}:}{For internal use}
  }
}
\section{Methods}{
  \describe{
    \item{\code{handshake()}:}{Performs an OAuth handshake using the
      information provided}
    \item{\code{isVerified()}:}{Returns the current verification status}
    \item{\code{OAuthRequest(URL, method="GET")}:}{Will sign the URL provided
      and make an HTTP request using either \code{POST} or \code{GET},
      determined by \code{method}, defaulting to \code{GET}.  NOTE:  The
    \code{URL} argument will be run through \code{\link{URLencode}}, so
    doing this step beforehand might lead to bad behavior!}
    \item{\code{initialize(needsVerifier, ...)}:}{ For internal use}
  }
}

\details{
  The OAuth class is currently implemented as a reference class.
  An instance of a generator for this class is provided as a convenience
  to the user as it is configured to handle most standard cases.  To
  access this generator, use the object \code{OAuthFactory}.  See the
  \code{examples} section below for an example of how to instantiate an
  object of class \code{OAuth}.

  In almost all cases, saving an \code{OAuth} object after handshake
  and loading it into future sessions will allow it to remain authorized
  without needing any manual intervention that might have been performed
  initially, such as the PIN step with Twitter authentication.
  
   The \code{needsVerifier} argument is optional and defaults to
   \code{TRUE}.  In almost all cases, the default should be used, the
   option is primarily provided to enable the examples as the keys
   provided by the examples are already signed.  If you feel that you're
   in a situation where this should be set to \code{FALSE}, it's best to double
   check this.
}

\section{Extends}{
  All reference classes extend and inherit methods from
  \code{"\linkS4class{envRefClass}"}.
}

\references{
liboauth: http://liboauth.sourceforge.net/
}

\author{
Jeff Gentry
}

\seealso{\code{\link{setRefClass}}}

\examples{
   ## This example uses a test case from liboauth and the
   ## keys are already pre-signed.  This is an example of
   ## one of the few times \code{needsVerifier} would be \code{FALSE}.
    
   reqURL <- "http://term.ie/oauth/example/request_token.php"
   accessURL <- "http://term.ie/oauth/example/access_token.php"
   authURL <- "NORMALLY YOU NEED THIS"
   cKey <- "key"
   cSecret <- "secret"
   testURL <- "http://term.ie/oauth/example/echo_api.php?method=foo bar"

   credentials <- OAuthFactory$new(consumerKey=cKey,
                                   consumerSecret=cSecret,
                                   requestURL=reqURL,
				   accessURL=accessURL,
				   authURL=authURL,
                                   needsVerifier=FALSE)
   credentials$handshake()
   ## the GET isn't strictly necessary as that's the default
   credentials$OAuthRequest(testURL, "GET")
}

\keyword{classes}
