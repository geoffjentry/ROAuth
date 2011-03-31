#include "ROAuth.h"

SEXP ROAuth_HTTP(SEXP url, SEXP consumerKey,
		 SEXP consumerSecret, SEXP oauthKey,
		 SEXP oauthSecret, SEXP customHeader, int method) { 
  char *req_url;
  char *reply;
  char *args = NULL;
  char *oauthKeyStr = NULL;
  char *oauthSecretStr = NULL;
  char *customHeaderStr = NULL;
  int tmpStrLen;
  char methodStr[10];


  /* Double check data types for the inputs - the oauth tokens can
     be string or NULL */
  if (!isString(url))
    error("'url' must be a string");
  if (!isString(consumerKey))
    error("'consumerKey' must be a string");
  if (!isString(consumerSecret))
    error("'consumerSecret' must be a string");
  if ((!isNull(oauthKey)) && (!isString(oauthKey)))
    error("'oauthKey' must be a string or NULL");
  if ((!isNull(oauthSecret)) && (!isString(oauthSecret)))
    error("'oauthSecret' must be a string or NULL");
  if ((!isNull(customHeader)) && (!isString(customHeader)))
    error("'customHeader' must be a string or NULL");

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
  if (!isNull(customHeader)) {
    tmpStrLen = strlen(STR(customHeader)) + 1;
    customHeaderStr = (char *)R_alloc(tmpStrLen, sizeof(char));
    strncpy(customHeaderStr, STR(customHeader), tmpStrLen);
  }

  /* sign the request and then fire it out */
  if (method)
    strcpy(methodStr, "GET");
  else
    strcpy(methodStr, "POST");
  req_url = oauth_sign_url2(STR(url), &args, OA_HMAC, methodStr,
			    STR(consumerKey), STR(consumerSecret),
			    oauthKeyStr, oauthSecretStr);
  if (method == GET) {
    reply = oauth_http_get2(req_url, args, customHeaderStr);
  } else {
    reply = oauth_http_post2(req_url, args, customHeaderStr);
  }

  /* liboauth requires freeing up some of these vars */
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
		 SEXP oauthSecret, SEXP customHeader) {
  return(ROAuth_HTTP(url, consumerKey, consumerSecret,
		     oauthKey, oauthSecret, customHeader, POST));
}

SEXP ROAuth_GET(SEXP url, SEXP consumerKey,
		SEXP consumerSecret, SEXP oauthKey,
		SEXP oauthSecret, SEXP customHeader) {
  return(ROAuth_HTTP(url, consumerKey, consumerSecret,
		     oauthKey, oauthSecret, customHeader, GET));
}
  
