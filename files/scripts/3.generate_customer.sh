#!/bin/bash

CERT_HOME=$HOME/ca
ROOTCA_HOME=$CERT_HOME/root
INTERMEDIATE_HOME=$CERT_HOME/intermediate
CUSTOMER_HOME=$CERT_HOME/customer

# make /home/hskim/certificate directory
if [ ! -d "$CERT_HOME" ]; then
	mkdir $CERT_HOME
fi

# make /home/hskim/certificate/rootca directory
if [ -d "$CUSTOMER_HOME" ]; then
	rm -rf $CUSTOMER_HOME
fi

mkdir -p $CUSTOMER_HOME

cp -af customer_openssl.cnf $CUSTOMER_HOME/openssl.cnf
cd $CUSTOMER_HOME
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
openssl genrsa -out private/customer.key.pem 2048
chmod 666 private/customer.key.pem

# generate customer ca csr
openssl req -config openssl.cnf \
			-new -sha256 \
			-subj "/C=KR/ST=Seoul/O=Kims Ltd/OU=R&D/CN=Kims Ltd CUSTOMER" \
			-key private/customer.key.pem \
			-out csr/customer.csr.pem

# generate intermediate ca certificate
openssl ca -config openssl.cnf \
			-extensions usr_cert \
			-days 365 -notext -md sha256 \
			-in csr/customer.csr.pem \
			-out certs/customer.cert.pem


# identify intermdiate certificate
openssl x509 -noout -text -in certs/customer.cert.pem

# verify the intermediate certificate against the root certificate
openssl verify -CAfile $INTERMEDIATE_HOME/certs/ca-chain.cert.pem \
				certs/customer.cert.pem

