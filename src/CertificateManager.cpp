#include "CertificateManager.hpp"
#include "OpensslRsaKeyWrapper.hpp"
#include "OpensslCsrWrapper.hpp"
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

	if(upOpenCsr->getX509Req() == NULL)
	{
		return false;
	}

	if(upOpenCsr->write(x509Req) == false)
	{
		return false;
	}

	return true;
}

bool CertificateManager::sign()
{
	return true;
}

bool CertificateManager::verify()
{
	return true;
}
