#ifndef OAUTH_HELPER_H
#define OAUTH_HELPER_H

#include "Poco/Random.h"
#include "Poco/HMACEngine.h"
#include "Poco/SHA1Engine.h"
#include "Poco/Base64Encoder.h"
#include "Poco/Timestamp.h"
#include "Poco/String.h"

#include <ctime>
#include <iostream>
#include <vector>
#include <math.h>
#include <sstream>

using Poco::Random;
using Poco::DigestEngine;
using Poco::HMACEngine;
using Poco::SHA1Engine;
using Poco::Timestamp;
using Poco::toUpper;

namespace Helper{

	long static timestamp(){ 
		Timestamp now;
		return floor(Timestamp::fromEpochTime(now.epochTime()).epochMicroseconds()/1000000.0);
	}

	std::string static hmacSha1Base64(const std::string & key, const std::string & data){
		HMACEngine<SHA1Engine> hmac(key);
		hmac.update(data);
		const DigestEngine::Digest& digest = hmac.digest();

		std::string str;
		for(int i = 0 ; i < digest.size(); i++) str += digest.at(i);

		std::istringstream in(str);
		std::ostringstream out;
		Poco::Base64Encoder b64out(out);

		std::copy(std::istreambuf_iterator<char>(in),
	            std::istreambuf_iterator<char>(),
	            std::ostreambuf_iterator<char>(b64out));

		b64out.close();
		return out.str();
	}

	std::string static pick(const std::vector<int> & xs){
		Random rnd;
		rnd.seed();

		char x = xs.at(rnd.next(xs.size()));
		std::string s;
		return s += x;
	}

	std::string static identifier(const int & n, const bool &f = false){

		Random rnd;
		rnd.seed();

		std::vector<int> letters;
		if(f) letters.push_back('_');

		int i = 0;
		for(i = 0; i < 26; i++) letters.push_back('A' + i);
		for(i = 0; i < 26; i++) letters.push_back('a' + i);

		std::vector<int> words = std::vector<int>(letters);
		for (i = 0; i < 10; i++) words.push_back('0' + i);

		std::string output = pick(letters);
		for (i = 1; i < n; i++) output += pick(words);
		return output;
		
	}

	std::string static char2hex( char dec )
	{
	    char dig1 = (dec&0xF0)>>4;
	    char dig2 = (dec&0x0F);
	    if ( 0<= dig1 && dig1<= 9) dig1+=48;    //0,48inascii
	    if (10<= dig1 && dig1<=15) dig1+=97-10; //a,97inascii
	    if ( 0<= dig2 && dig2<= 9) dig2+=48;
	    if (10<= dig2 && dig2<=15) dig2+=97-10;

	    std::string r;
	    r.append( &dig1, 1);
	    r.append( &dig2, 1);
	    return toUpper(r);
	}

	std::string static urlencode(const std::string &c)
	{
    
	    std::string escaped="";

	    int max = c.length();
	    
	    for(int i=0; i<max; i++)
	    {
	        if ( (48 <= c[i] && c[i] <= 57) ||//0-9
	             (65 <= c[i] && c[i] <= 90) ||//abc...xyz
	             (97 <= c[i] && c[i] <= 122) || //ABC...XYZ
	             (c[i]=='~' || 
	             	c[i]=='!' || 
	             	c[i]=='*' || 
	             	c[i]=='(' || 
	             	c[i]==')' || 
	             	c[i]=='\''|| 
	             	c[i]=='.' ||
	             	c[i]=='_' ||
	             	c[i]=='-'
	             	)
	        )
	        {
	            escaped.append( &c[i], 1);
	        }
	        else
	        {
	            escaped.append("%");
	            escaped.append( char2hex(c[i]) );//converts char 255 to string "ff"
	        }
	    }
    	return escaped;
	}
}
#endif

