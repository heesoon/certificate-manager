#!/bin/bash

cd ../
cd root/ca

# openssl genrsa -ase256 -out private/ca.key.pen 4096
# chmod 400 private/ca.key.pem

# generate key pair
openssl genrsa -out private/ca.key.pem 4096

# generate root ca certficate
openssl req -config openssl.cnf \
			-subj "/C=KR/ST=Seoul/O=Kims Ltd/OU=R&D/CN=Kims Ltd Root CA" \
			-key private/ca.key.pem \
			-nodes \
			-new -x509 -days 7300 -sha256 -extensions v3_ca \
			-out certs/ca.cert.pem

# verify the root certificate
openssl x509 -noout -text -in certs/ca.cert.pem
