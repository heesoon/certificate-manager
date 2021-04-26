#include <string>
#include <memory>
#include "Log.hpp"
#include "OpensslBioWrapper.hpp"
#include "OpensslRsaKeyWrapper.hpp"

void testKey()
{
	bool ret = false;
	const std::string outputKeyFilename = "privateKey.pem";
	std::unique_ptr<OpensslRsaKeyWrapper> upOpenRsaPrivateKey(new OpensslRsaKeyWrapper());
	
	ret = upOpenRsaPrivateKey->open(outputKeyFilename, 'w', FORMAT_PEM, 2048);
	if(ret == false)
	{
		return;
	}

	ret = upOpenRsaPrivateKey->write(PKEY_TYPE_T::PKEY_PRIVATE_KEY, outputKeyFilename, NULL, NULL);
	//ret = upOpenRsaPrivateKey->write(PKEY_TYPE_T::PKEY_PRIVATE_KEY, outputKeyFilename, "12345", "AES-256-CBC");
	if(ret == false)
	{
		return;
	}

	PmLogDebug("[%s, %d] Success", __FUNCTION__, __LINE__);
}

int main()
{
	testKey();
	return 0;
}