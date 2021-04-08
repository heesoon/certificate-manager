#!/bin/bash

cd ../
mkdir -p root/ca
cd root/ca
mkdir certs crl newcerts private
chmod 700 private
touch index.txt
echo 1000 > serial
cp -af ../../scripts/root_openssl.cnf openssl.cnf
