#!/bin/bash

CERT_HOME=$HOME/certificates
ROOTCA_HOME=$CERT_HOME/rootca
INTERMEDIATE_HOME=$CERT_HOME/intermediate

# make /home/hskim/certificate directory
if [! -d "$CERT_HOME" ]; then
	mkdir $CERT_HOME
fi

# make /home/hskim/certificate/rootca directory
if [ -d "$INTERMEDIATE_HOME" ]; then
	rm -rf $INTERMEDIATE_HOME
fi

mkdir -p $INTERMEDIATE_HOME

cp -af intermediate_openssl.cnf $INTERMEDIATE_HOME/openssl.cnf
cd $INTERMEDIATE_HOME
mkdir certs crl csr newcerts private
chmod 700 private
touch index.txt
touch index.txt.attr
echo 1000 > serial
touch crlnumber
echo 1000 > crlnumber

# openssl genrsa -ase256 -out private/ca.key.pen 4096
# chmod 400 private/ca.key.pem

# generate key pair
openssl genrsa -out private/intermediate.key.pem 4096
chmod 666 private/intermediate.key.pem

# generate intermediate ca csr
openssl req -config openssl.cnf \
			-new -sha256 \
			-subj "/C=KR/ST=Seoul/O=Kims Ltd/OU=R&D/CN=Kims Ltd Intermediate CA" \
			-key private/intermediate.key.pem \
			-out csr/intermediate.csr.pem

# generate intermediate ca certificate
openssl ca -config openssl.cnf \
			-extensions v3_intermediate_ca \
			-days 3650 -notext -md sha256 \
			-in csr/intermediate.csr.pem \
			-out certs/intermediate.cert.pem


# identify intermdiate certificate
openssl x509 -noout -text -in certs/intermediate.cert.pem

# verify the intermediate certificate against the root certificate
openssl verify -CAfile $ROOTCA_HOME/certs/ca.cert.pem \
				certs/intermediate.cert.pem
				
# generate certificate chain
cat $INTERMEDIATE_HOME/certs/intermediate.cert.pem \
	$ROOTCA_HOME/certs/ca.cert.pem > $INTERMEDIATE_HOME/certs/ca-chain.cert.pem

