#!/bin/bash

# https://www.openssl.org/docs/man1.0.2/man1/openssl-req.html

rm -rf ./certs
mkdir ./certs

# generate private/public key pair by genrsa without password
#echo "generate key pairs without password"
#openssl genrsa -out ./certs/rootca_key.pem 4096

# generate key pairs with password and encryt
#openssl genrsa -aes256 -passout:hskim -out encrypted_rootca_key.pem 2048
# decrypt above key pairs
#openssl rsa -outform der -in encrypted_rootca_key.pem -passin:hskim -out rootca_key.pem

# generate csr

#openssl req -new -key ./certs/rootca_key.pem -config rootca_openssl.cnf -out ./certs/csr.pem

openssl req \
		-x509 -newkey rsa:4096 -keyout ./certs/rootca_key.pem -out ./certs/rootca.cert \
		-config rootca_openssl.cnf -nodes	\
		-days 3600

# verify pem

openssl x509 -text -noout -in ./certs/rootca.cert


