#include "ROAuth.h"

SEXP ROAuth_HTTP(SEXP url, SEXP consumerKey,
		 SEXP consumerSecret, SEXP oauthKey,
		 SEXP oauthSecret, int method) { 
  char *req_url;
  char *reply;
  char *args = NULL;
  char *oauthKeyStr = NULL;
  char *oauthSecretStr = NULL;
  int tmpStrLen;

  if (!isString(url))
    error("'url' must be a string");
  if (!isString(consumerKey))
    error("'consumerKey' must be a string");
  if (!isString(consumerSecret))
    error("'consumerSecret' must be a string");
  if (!isString(oauthKey))
    error("'oauthKey' must be a string");
  if (!isString(oauthSecret))
    error("'oauthSecret' must be a string");

  if (!isNull(oauthKey)) {
    tmpStrLen = strlen(STR(oauthKey)) + 1;
    oauthKeyStr = (char *)R_alloc(tmpStrLen, sizeof(char));
    strncpy(oauthKeyStr, STR(oauthKey), tmpStrLen);
  }
  
  if (!isNull(oauthSecret)) {
    tmpStrLen = strlen(STR(oauthSecret)) + 1;
    oauthSecretStr = (char *)R_alloc(tmpStrLen, sizeof(char));
    strncpy(oauthSecretStr, STR(oauthSecret), tmpStrLen);
  }

  req_url = oauth_sign_url2(STR(url), &args, OA_HMAC, "POST",
			    STR(consumerKey), STR(consumerSecret),
			    oauthKeyStr, oauthSecretStr);

  if (method == GET) {
    printf("Here\n");
    reply = oauth_http_get(req_url, args);
  } else {
    printf("There\n");
    reply = oauth_http_post(req_url, args);
  }
  if (req_url)
    free(req_url);
  if (args)
    free(args);

  if (!reply)
    error("No response from server");

  return(mkString(reply));
}

SEXP ROAuth_POST(SEXP url, SEXP consumerKey,
		 SEXP consumerSecret, SEXP oauthKey,
		 SEXP oauthSecret) {
  return(ROAuth_HTTP(url, consumerKey, consumerSecret,
		     oauthKey, oauthSecret, POST));
}

SEXP ROAuth_GET(SEXP url, SEXP consumerKey,
		 SEXP consumerSecret, SEXP oauthKey,
		 SEXP oauthSecret) {
  return(ROAuth_HTTP(url, consumerKey, consumerSecret,
		     oauthKey, oauthSecret, GET));
}
  
