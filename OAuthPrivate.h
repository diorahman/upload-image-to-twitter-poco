#ifndef OAUTH_PRIVATE_H
#define OAUTH_PRIVATE_H

#include <string>
#include "OAuthTypes.h"

class OAuthPrivate{

public:
	OAuthPrivate();
	~OAuthPrivate();

	enum RequestType { RequestToken, AccessToken, Resource, ResourceStream};

	std::string baseString(const std::string & method, const std::string & url, const std::string & paramStr);
	std::string signingKey(const std::string & consumerSecretKey, const std::string & oauthTokenSecretKey);
	std::string signature(const std::string signingKeyStr, const std::string & baseStr);
	std::string paramsString(Params params);
	std::string buildAuthHeader(const std::string & method, const std::string & url, Params data, const std::string & verifier = "");

	// buildRequest();

	void requestToken();
	void accesToken();
	void resource();

	void resourceFile(const std::string method, const std::string url, const std::string & filename);

	std::string consumerKey;
	std::string consumerSecret;
	std::string oauthToken;
	std::string oauthTokenSecret;

};

#endif