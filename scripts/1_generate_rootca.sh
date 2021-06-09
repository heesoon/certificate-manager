#!/bin/bash

CERT_HOME=$HOME/ca
ROOTCA_HOME=$CERT_HOME/root

# make /home/hskim/ca directory
if [! -d "$CERT_HOME"]; then
	mkdir $CERT_HOME
fi

# make /home/hskim/ca/root directory
if [ -d "$ROOTCA_HOME"]; then
	rm -rf $ROOTCA_HOME
fi

mkdir -p $ROOTCA_HOME

cp -af root_openssl.cnf $ROOTCA_HOME/openssl.cnf
cd $ROOTCA_HOME
mkdir certs crl newcerts private
touch index.txt
echo 1000 > serial

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
