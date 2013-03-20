#include "Poco/String.h"
#include "Poco/URI.h"
#include "Poco/HashMap.h"
#include "Poco/NumberFormatter.h"

#include "Poco/Net/HTTPClientSession.h"
#include "Poco/Net/HTTPSClientSession.h"
#include "Poco/Net/HTTPRequest.h"
#include "Poco/Net/HTTPResponse.h"
#include "Poco/Net/HTMLForm.h"
#include "Poco/Net/HTTPCredentials.h"
#include "Poco/StreamCopier.h"
#include "Poco/NullStream.h"
#include "Poco/Path.h"
#include "Poco/Exception.h"
#include "Poco/Net/PartSource.h"
#include "Poco/Net/FilePartSource.h"

#include "OAuthPrivate.h"
#include "OAuthHelper.h"

using Poco::NumberFormatter;
using Poco::toUpper;
using Poco::URI;

using Poco::Net::HTTPClientSession;
using Poco::Net::HTTPSClientSession;
using Poco::Net::HTTPRequest;
using Poco::Net::HTTPResponse;
using Poco::Net::HTTPMessage;
using Poco::StreamCopier;
using Poco::Path;
using Poco::Exception;

OAuthPrivate::OAuthPrivate(){}
OAuthPrivate::~OAuthPrivate(){}

std::string OAuthPrivate::baseString(const std::string & method, const std::string & url, const std::string & paramStr){

	std::string baseStr = toUpper(method) + "&" + Helper::urlencode(url);
	baseStr += "&" + Helper::urlencode(paramStr);
    return baseStr;
}

std::string OAuthPrivate::signingKey(const std::string & consumerSecretKey, const std::string & oauthTokenSecretKey){
	return URI(consumerSecretKey).toString() + "&" + URI(oauthTokenSecretKey).toString();
}

std::string OAuthPrivate::signature(const std::string signingKeyStr, const std::string & baseStr){
	return Helper::hmacSha1Base64(signingKeyStr, baseStr);
}

std::string OAuthPrivate::paramsString(Params params){

    std::string paramStr;

    ParamsIterator it;
    for(it = params.begin(); it != params.end(); it++){
    	std::string key = (*it).first;
    	std::string val = (*it).second;
        
        paramStr += URI(key).toString() + "=" + Helper::urlencode(val) + "&";
    }
    return paramStr.substr(0, paramStr.length() - 1);
}


std::string OAuthPrivate::buildAuthHeader(const std::string & method, const std::string & url, Params data, const std::string & verifier){

	Params params;
	params.insert(std::pair<std::string, std::string>("oauth_consumer_key", consumerKey));
	params.insert(std::pair<std::string, std::string>("oauth_nonce", Helper::identifier(42)));
	//params.insert(std::pair<std::string, std::string>("oauth_nonce", "Qr2DJzLO3iZCRnqN7hRvJCX5VZFk62fh2Qrbx3Snzl"));
	params.insert(std::pair<std::string, std::string>("oauth_signature_method", "HMAC-SHA1"));
	params.insert(std::pair<std::string, std::string>("oauth_timestamp", NumberFormatter::format(Helper::timestamp())));
	//params.insert(std::pair<std::string, std::string>("oauth_timestamp", "1363740223"));

	params.insert(std::pair<std::string, std::string>("oauth_version", "1.0"));

    if(!verifier.empty()) 
    	params.insert(std::pair<std::string, std::string>("oauth_verifier", verifier));

    if(!oauthToken.empty())
    	params.insert(std::pair<std::string, std::string>("oauth_token", oauthToken));

    params.insert(data.begin(), data.end());
    params.insert(std::pair<std::string, std::string>("oauth_signature", signature(signingKey(consumerSecret, oauthTokenSecret), baseString(method, url, paramsString(params)))));

    std::string authStr;

    ParamsIterator it;
    for(it = params.begin(); it != params.end(); it++){
    	 std::string key = (*it).first;
    	 std::string val = (*it).second;

    	 authStr += URI(key).toString() + "=\"" + Helper::urlencode(val) + "\", ";
    }

    return authStr.substr(0, authStr.length() - 2);
}	

void OAuthPrivate::requestToken(){}
void OAuthPrivate::accesToken(){}
void OAuthPrivate::resource(){}

void OAuthPrivate::resourceFile(const std::string method, const std::string url, const std::string & filename, const std::string status){
	std::string authStr = buildAuthHeader(method, url, Params());
	authStr = "OAuth " + authStr;

	URI uri(url);
	std::string path(uri.getPathAndQuery());
	if (path.empty()) path = "/";

	const Poco::Net::Context::Ptr context( new Poco::Net::Context(Poco::Net::Context::CLIENT_USE, "", "", "cacert.pem"));
	HTTPSClientSession session(uri.getHost(), uri.getPort(), context);
	HTTPRequest request(HTTPRequest::HTTP_POST, path, HTTPMessage::HTTP_1_1);
	HTTPResponse response;

	Poco::Net::HTMLForm form;
	form.setEncoding(Poco::Net::HTMLForm::ENCODING_MULTIPART);

	form.set("status", status);
	
	form.addPart("media[]", new Poco::Net::FilePartSource(filename, filename, "application/octet-stream"));
	form.prepareSubmit(request);

	request.set("Authorization", authStr);
	
	std::ostream & ostr = session.sendRequest(request);
	form.write(ostr);

	std::istream& rs = session.receiveResponse(response);
	std::cout << response.getStatus() << " " << response.getReason() << std::endl;

	if (response.getStatus() != Poco::Net::HTTPResponse::HTTP_UNAUTHORIZED)
	{
		StreamCopier::copyStream(rs, std::cout);
	}
	else
	{
		Poco::NullOutputStream null;
		StreamCopier::copyStream(rs, null);
	}
}


