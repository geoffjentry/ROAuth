\name{OAuth-class}
\Rdversion{1.1}
\docType{class}
\alias{OAuth-class}

\title{Class "OAuth"}
\description{
%%  ~~ A concise (1-5 lines) description of what the class is. ~~
}
\section{Extends}{

All reference classes extend and inherit methods from \code{"\linkS4class{envRefClass}"}.

}
\references{
%%  ~~put references to the literature/web site here~~
}
\author{
%%  ~~who you are~~
}
\note{
%%  ~~further notes~~
}

%% ~Make other sections like Warning with \section{Warning }{....} ~

\seealso{
%%  ~~objects to See Also as \code{\link{~~fun~~}}, ~~~
%%  ~~or \code{\linkS4class{CLASSNAME}} for links to other classes ~~~
}
\examples{
showClass("OAuth")
}
\keyword{classes}
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
