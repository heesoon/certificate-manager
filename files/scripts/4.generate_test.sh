#!/bin/bash

CERT_HOME=$HOME/ca
ROOTCA_HOME=$CERT_HOME/root
INTERMEDIATE_HOME=$CERT_HOME/intermediate
CUSTOMER_HOME=$CERT_HOME/customer
TEST_HOME=$CERT_HOME/test

# make /home/hskim/ca directory
if [ ! -d "$CERT_HOME" ]; then
	mkdir $CERT_HOME
fi

# make /home/hskim/certificate/rootca directory
if [ -d "$TEST_HOME" ]; then
	rm -rf $TEST_HOME
fi

mkdir -p $TEST_HOME
cd $TEST_HOME

# copy customer key, this certifiation will be signed by intermediate ca
cp -af $CUSTOMER_HOME/private/customer.key.pem ./

# copy intermediate ca private key and certification
cp -af $INTERMEDIATE_HOME/private/intermediate.key.pem ./
cp -af $INTERMEDIATE_HOME/certs/intermediate.cert.pem ./

# copy ca certification chain for verification
cp -af $INTERMEDIATE_HOME/certs/ca-chain.cert.pem ./

# copy configuration file
cp -af $CUSTOMER_HOME/openssl.cnf ./customer_openssl.cnf