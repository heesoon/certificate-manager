#include <string>
#include <memory>
#include "Log.hpp"
#include "OpensslBioWrapper.hpp"
#include "OpensslRsaKeyWrapper.hpp"

void testCreatePlainTextPrivateKey()
{
	bool ret = false;
	EVP_PKEY *pkey = NULL;

	const std::string outputKeyFilename = "plainTextPrivatekey.pem";
	std::unique_ptr<OpensslRsaKeyWrapper> upOpenRsaPrivateKey(new OpensslRsaKeyWrapper());
	
	ret = upOpenRsaPrivateKey->open(outputKeyFilename, 'w', FORMAT_PEM, 2048);
	if(ret == false)
	{
		PmLogError("[%s, %d]", __FUNCTION__, __LINE__);
		return;
	}

	pkey = upOpenRsaPrivateKey->getPkey();
	if(pkey == NULL)
	{
		PmLogError("[%s, %d]", __FUNCTION__, __LINE__);
		return;
	}

	ret = upOpenRsaPrivateKey->write(pkey, PKEY_TYPE_T::PKEY_PRIVATE_KEY, "", "");
	if(ret == false)
	{
		return;
	}

	PmLogDebug("[%s, %d] Success", __FUNCTION__, __LINE__);
}

void testCreateEncryptedPrivateKey()
{
	bool ret = false;
	EVP_PKEY *pkey = NULL;

	const std::string outputKeyFilename = "encryptedPrivatekey.pem";
	std::unique_ptr<OpensslRsaKeyWrapper> upOpenRsaPrivateKey(new OpensslRsaKeyWrapper());
	
	ret = upOpenRsaPrivateKey->open(outputKeyFilename, 'w', FORMAT_PEM, 2048);
	if(ret == false)
	{
		return;
	}

	pkey = upOpenRsaPrivateKey->getPkey();
	if(pkey == NULL)
	{
		PmLogError("[%s, %d]", __FUNCTION__, __LINE__);
		return;
	}	

	//ret = upOpenRsaPrivateKey->write(pkey, PKEY_TYPE_T::PKEY_PRIVATE_KEY, "123456789", "AES-256-CBC");
	ret = upOpenRsaPrivateKey->write(pkey, PKEY_TYPE_T::PKEY_PRIVATE_KEY, "12345678", "AES-256-CBC");
	if(ret == false)
	{
		return;
	}

	PmLogDebug("[%s, %d] Success", __FUNCTION__, __LINE__);
}

int main()
{
	testCreatePlainTextPrivateKey();
	testCreateEncryptedPrivateKey();
	return 0;
}