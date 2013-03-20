all: oauth-test

test: main.o OAuthPrivate.o
	g++ main.o OAuthPrivate.o -o test -lPocoUtil -lPocoNet -lPocoNetSSL -lPocoXML -lPocoCrypto -lPocoFoundation -lssl -lcrypto -lz -ldl

main.o: main.cpp
	g++ -c main.cpp

OAuthPrivate.o: OAuthPrivate.cpp
	g++ -c OAuthPrivate.cpp

clean: 
	rm -fr *o test