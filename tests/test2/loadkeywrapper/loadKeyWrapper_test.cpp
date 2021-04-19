#include <iostream>
#include <string>
#include <memory>
#include "loadKeyWrapper.hpp"

// pirvate key load test
void testPrivateKeyANSILoadKeyWrapper()
{
	std::string inputKeyFilename = "/home/hskim/certificates/rootca/private/ca.key.pem";
	std::unique_ptr<LoadKeyWrapper> upLoadKeyWrapper(new LoadKeyWrapper());
	upLoadKeyWrapper->loadPrivateKey(inputKeyFilename, FORMAT_ASN1);
}

void testPrivateKeyPEMLoadKeyWrapper()
{
	std::string inputKeyFilename = "/home/hskim/certificates/rootca/private/ca.key.pem";
	std::unique_ptr<LoadKeyWrapper> upLoadKeyWrapper(new LoadKeyWrapper());
	upLoadKeyWrapper->loadPrivateKey(inputKeyFilename, FORMAT_PEM);
}

void testPrivateKeyPKCS12LoadKeyWrapper()
{
	std::string inputKeyFilename = "/home/hskim/certificates/rootca/private/ca.key.pem";
	std::unique_ptr<LoadKeyWrapper> upLoadKeyWrapper(new LoadKeyWrapper());
	upLoadKeyWrapper->loadPrivateKey(inputKeyFilename, FORMAT_PKCS12);
}

void testPrivateKeyPVKLoadKeyWrapper()
{
	std::string inputKeyFilename = "/home/hskim/certificates/rootca/private/ca.key.pem";
	std::unique_ptr<LoadKeyWrapper> upLoadKeyWrapper(new LoadKeyWrapper());
	upLoadKeyWrapper->loadPrivateKey(inputKeyFilename, FORMAT_PVK);
}

// public key load test
void testPublicKeyANSILoadKeyWrapper()
{
	std::string inputKeyFilename = "/home/hskim/certificates/rootca/private/ca.key.pem";
	std::unique_ptr<LoadKeyWrapper> upLoadKeyWrapper(new LoadKeyWrapper());
	upLoadKeyWrapper->loadPublicKey(inputKeyFilename, FORMAT_ASN1);
}

void testPublicKeyPEMLoadKeyWrapper()
{
	std::string inputKeyFilename = "/home/hskim/certificates/rootca/private/ca.key.pem";
	std::unique_ptr<LoadKeyWrapper> upLoadKeyWrapper(new LoadKeyWrapper());
	upLoadKeyWrapper->loadPublicKey(inputKeyFilename, FORMAT_PEM);
}

void testPublicKeyPEMRSALoadKeyWrapper()
{
	std::string inputKeyFilename = "/home/hskim/certificates/rootca/private/ca.key.pem";
	std::unique_ptr<LoadKeyWrapper> upLoadKeyWrapper(new LoadKeyWrapper());
	upLoadKeyWrapper->loadPublicKey(inputKeyFilename, FORMAT_PEMRSA);
}

int main()
{
	// public key load test
	testPublicKeyANSILoadKeyWrapper();
	testPublicKeyPEMLoadKeyWrapper();
	testPublicKeyPEMRSALoadKeyWrapper();
	
	// Private key load test
	testPrivateKeyANSILoadKeyWrapper();
	testPrivateKeyPEMLoadKeyWrapper();
	testPrivateKeyPKCS12LoadKeyWrapper();
	testPrivateKeyPVKLoadKeyWrapper();

	return 0;
}