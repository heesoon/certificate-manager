#!/bin/bash

cd ../
cd root/ca
mkdir intermediate
cd intermediate
mkdir certs crl csr newcerts private
chmod 700 private
touch index.txt
echo 1000 > serial
touch crlnumber
echo 1000 > crlnumber
cp -af ../../../scripts/intermediate_openssl.cnf ./openssl.cnf

#  move to root/ca directory
cd ..

# openssl genrsa -ase256 -out private/ca.key.pen 4096
# chmod 400 private/ca.key.pem

# generate key pair
openssl genrsa -out intermediate/private/intermediate.key.pem 4096
chmod 666 intermediate/private/intermediate.key.pem

# generate intermediate ca csr
openssl req -config intermediate/openssl.cnf \
			-new -sha256 \
			-subj "/C=KR/ST=Seoul/O=Kims Ltd/OU=R&D/CN=Kims Ltd Intermediate CA" \
			-key intermediate/private/intermediate.key.pem \
			-out intermediate/csr/intermediate.csr.pem

# generate intermediate ca certificate
openssl ca -config intermediate/openssl.cnf \
			-extensions v3_intermediate_ca \
			-days 3650 -notext -md sha256 \
			-in intermediate/csr/intermediate.csr.pem \
			-out intermediate/certs/intermediate.cert.pem


# identify intermdiate certificate
openssl x509 -noout -text -in intermediate/intermediate.cert.pem

# verify the intermediate certificate against the root certificate
openssl verify -CASfile certs/ca.cert.pem \
				intermediate/certs/intermediate.cert.pem

