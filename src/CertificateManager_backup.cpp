#include "CertificateManager.hpp"
#include "OpensslRsaKeyWrapper.hpp"
#include "OpensslCsrWrapper.hpp"
#include "OpensslCaWrapper.hpp"
#include "Log.hpp"
#include <memory>

CertificateManager::CertificateManager()
{
}

bool CertificateManager::generateKey(const std::string &outputKeyFilename, int keySize)
{
	EVP_PKEY *pkey = NULL;

	if(outputKeyFilename.empty())
	{
		return false;
	}

	if(keySize <= 1024 || keySize >= 16384)
	{
		return false;
	}

	OpensslRsaKeyWrapper opensslRsaKeyWrapper;

	if(opensslRsaKeyWrapper.open(outputKeyFilename, 'w', FORMAT_PEM, keySize) == false)
	{
		return false;
	}

	pkey = opensslRsaKeyWrapper.getPkey();
	if(pkey == NULL)
	{
		return false;
	}

	if(opensslRsaKeyWrapper.write(pkey, PKEY_TYPE_T::PKEY_PRIVATE_KEY, "", "") == false)
	{
		return false;
	}

	return true;
}

bool CertificateManager::csr(const std::string &outputCsrFilename, const std::string &inputPrivateKey, const std::string &commonName)
{
	X509_REQ *x509Req = NULL;

	subject_t subject;
	subject.commonName = commonName;
	subject.countryName = "KR";
	subject.stateOrProvinceName = "Seoul";
	subject.localityName = "Seoul";
	subject.organizationName = "IDSW R&D Divisions";
	subject.emailAddress = "idsw@idsw.lge.com";

	//const std::string inputConfFileName = @WEBOS_INSTALL_WEBOS_SERVICESDIR@ + "/scripts/customer_openssl.cnf";
	const std::string inputConfFileName = "/usr/palm/services/com.webos.service.certificatemanager/scripts/customer_openssl.cnf";

	std::unique_ptr<OpensslCsrWrapper> upOpenCsr(new OpensslCsrWrapper());
	if(upOpenCsr == nullptr)
	{
		return false;
	}

	if(upOpenCsr->open(outputCsrFilename, 'w', FORMAT_PEM) == false)
	{
		return false;
	}

	if(upOpenCsr->makeCsr(inputConfFileName, inputPrivateKey, subject) == false)
	{
		return false;
	}

	x509Req = upOpenCsr->getX509Req();
	if(x509Req == NULL)
	{
		return false;
	}

	if(upOpenCsr->write(x509Req) == false)
	{
		return false;
	}

	return true;
}

bool CertificateManager::sign(const std::string &outputCertFile, const std::string &inputCsrFile)
{
	X509 *x509 = NULL;
	const std::string inputConfigFile = "/usr/palm/services/com.webos.service.certificatemanager/scripts/customer_openssl.cnf";

	std::unique_ptr<OpensslCaWrapper> upOpenCa(new OpensslCaWrapper());
	if(upOpenCa->open(outputCertFile, 'w', FORMAT_PEM) == false)
	{
		return false;
	}

	if(upOpenCa->generateCertSignedByCa(inputConfigFile, inputCsrFile) == false)
	{
		return false;
	}

	x509 = upOpenCa->getX509();
	if(x509 == NULL)
	{
		return false;
	}

	if(upOpenCa->write(x509) == false)
	{
		return false;
	}

	return true;
}

bool CertificateManager::verify(const std::string &inputCertFile)
{
	const std::string inputCaChainFile = "/usr/palm/services/com.webos.service.certificatemanager/scripts/ca-chain.cert.pem";
	std::unique_ptr<OpensslCaWrapper> upOpenCa(new OpensslCaWrapper());

	if(upOpenCa->verifyByCa(inputCaChainFile, inputCertFile) == false)
	{
		return false;
	}

	return true;
}
