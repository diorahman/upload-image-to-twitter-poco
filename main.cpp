#include <iostream>
#include "OAuthPrivate.h"
#include "OAuthHelper.h"

int main(){
	OAuthPrivate o;

	o.consumerKey = "TceD1lD6NKRVdIG5FTQlsg";
	o.consumerSecret =  "CVzmEXTIPFN5RKEIzCXErRJardCg6lfA0bX5wU8WHA";
	o.oauthToken = "924279246-QhiYSszZpnV706RGEyTtSufpX7tPNC57t8FdPZWl";
	o.oauthTokenSecret = "MmH158cSUv9Zum9YRJZrfkCJJdqKM9eV1FeoUvkygZo";

	o.resourceFile("POST", "https://upload.twitter.com/1/statuses/update_with_media.json", "test.png");
}