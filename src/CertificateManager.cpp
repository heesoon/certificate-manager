#include "CertificateManager.hpp"
#include "OpensslRsaKeyWrapper.hpp"
#include "Log.hpp"

CertificateManager::CertificateManager()
{
}

bool CertificateManager::generateKey(std::string outputKeyFilename, int keySize)
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

bool CertificateManager::csr()
{
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
