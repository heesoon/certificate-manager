#include <iostream>
#include <string>
#include <memory>
#include "bioWrapper.hpp"
#include "KeyWrapper.hpp"

// pirvate key load test
void testPrivateKeyANSILoadKeyWrapper()
{
	std::string inputKeyFilename = "/home/hskim/certificates/rootca/private/ca.key.pem";
	std::unique_ptr<KeyWrapper> upLoadKeyWrapper(new KeyWrapper());
	upLoadKeyWrapper->loadPrivateKey(inputKeyFilename, FORMAT_ASN1);
}

void testPrivateKeyPEMLoadKeyWrapper()
{
	std::string inputKeyFilename = "/home/hskim/certificates/rootca/private/ca.key.pem";
	std::unique_ptr<KeyWrapper> upLoadKeyWrapper(new KeyWrapper());
	upLoadKeyWrapper->loadPrivateKey(inputKeyFilename, FORMAT_PEM);
}

void testPrivateKeyPKCS12LoadKeyWrapper()
{
	std::string inputKeyFilename = "/home/hskim/certificates/rootca/private/ca.key.pem";
	std::unique_ptr<KeyWrapper> upLoadKeyWrapper(new KeyWrapper());
	upLoadKeyWrapper->loadPrivateKey(inputKeyFilename, FORMAT_PKCS12);
}

void testPrivateKeyPVKLoadKeyWrapper()
{
	std::string inputKeyFilename = "/home/hskim/certificates/rootca/private/ca.key.pem";
	std::unique_ptr<KeyWrapper> upLoadKeyWrapper(new KeyWrapper());
	upLoadKeyWrapper->loadPrivateKey(inputKeyFilename, FORMAT_PVK);
}

// public key load test
void testPublicKeyANSILoadKeyWrapper()
{
	std::string inputKeyFilename = "/home/hskim/certificates/rootca/private/ca.key.pem";
	std::unique_ptr<KeyWrapper> upLoadKeyWrapper(new KeyWrapper());
	upLoadKeyWrapper->loadPublicKey(inputKeyFilename, FORMAT_ASN1);
}

void testPublicKeyPEMLoadKeyWrapper()
{
	std::string inputKeyFilename = "/home/hskim/certificates/rootca/private/ca.key.pem";
	std::unique_ptr<KeyWrapper> upLoadKeyWrapper(new KeyWrapper());
	upLoadKeyWrapper->loadPublicKey(inputKeyFilename, FORMAT_PEM);
}

void testPublicKeyPEMRSALoadKeyWrapper()
{
	std::string inputKeyFilename = "/home/hskim/certificates/rootca/private/ca.key.pem";
	std::unique_ptr<KeyWrapper> upLoadKeyWrapper(new KeyWrapper());
	upLoadKeyWrapper->loadPublicKey(inputKeyFilename, FORMAT_PEMRSA);
}

void testKeyGenerationAndWrite()
{
	std::string outputKeyFilename = "createdPrivateKey.pem";
	std::unique_ptr<KeyWrapper> upLoadKeyWrapper(new KeyWrapper());
	upLoadKeyWrapper->createRsaKey(2048);
	upLoadKeyWrapper->savePrivateKey(outputKeyFilename, "123456789", "AES-256-GCM", FORMAT_PEM);
}

int main()
{
	testKeyGenerationAndWrite();

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