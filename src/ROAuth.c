#include "ROAuth.h"

/* FIXME:  Combined these into a single function using 
   functino pointer as the http function */

SEXP ROAuth_POST(SEXP url, SEXP consumerKey,
		 SEXP consumerSecret, SEXP oauthKey,
		 SEXP oauthSecret) {
  char *req_url;
  char *reply;
  char *args = NULL;
  char *oauthKeyStr = NULL;
  char *oauthSecretStr = NULL;

  /* FIXME:  isString should be used on all args*/

  /* FIXME: allocating fixed amnt of space */
  if (!isNull(oauthKey)) {
    oauthKeyStr = (char *)R_alloc(500, sizeof(char));
    strcpy(oauthKeyStr, STR(oauthKey));
  }
  
  if (!isNull(oauthSecret)) {
    oauthSecretStr = (char *)R_alloc(500, sizeof(char));
    strcpy(oauthSecretStr, STR(oauthSecret));
  }

  req_url = oauth_sign_url2(STR(url), &args, OA_HMAC, "POST",
			    STR(consumerKey), STR(consumerSecret),
			    oauthKeyStr, oauthSecretStr);
  reply = oauth_http_post(req_url, args);

  if (req_url)
    free(req_url);
  if (args)
    free(args);

  if (!reply)
    error("No response from server");

  return(mkString(reply));
}

SEXP ROAuth_GET(char *url, char *consumerKey,
		 char *consumerSecret, char *oauthKey,
		 char *oauthSecret) {
  char *req_url;
  char *reply;
  char *args = NULL;

  req_url = oauth_sign_url2(url, &args, OA_HMAC, "GET",
			    consumerKey, consumerSecret,
			    oauthKey, oauthSecret);
  reply = oauth_http_get(req_url, args);
  
  if (req_url)
    free(req_url);
  if (args)
    free(args);

  if (!reply)
    error("No response from server");

  return(mkString(reply));
}
