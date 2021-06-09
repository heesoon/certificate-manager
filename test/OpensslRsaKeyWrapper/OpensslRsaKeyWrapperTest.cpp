#include <string>
#include <memory>
#include "Log.hpp"
#include "gtest/gtest.h"
#include "OpensslBioWrapper.hpp"
#include "OpensslRsaKeyWrapper.hpp"

bool TC_CreateKeyWithoutPassword()
{
	EVP_PKEY *pkey = NULL;

	const std::string outputKeyFilename = "keyWithoutPassword.pem";
	std::unique_ptr<OpensslRsaKeyWrapper> upOpenRsaPrivateKey(new OpensslRsaKeyWrapper());

	if(upOpenRsaPrivateKey->open(outputKeyFilename, 'w', FORMAT_PEM, 2048) == false)
	{
		PmLogError("[%s, %d]", __FUNCTION__, __LINE__);
		return false;
	}

	pkey = upOpenRsaPrivateKey->getPkey();
	if(pkey == NULL)
	{
		PmLogError("[%s, %d]", __FUNCTION__, __LINE__);
		return false;
	}

	if(upOpenRsaPrivateKey->write(pkey, PKEY_TYPE_T::PKEY_PRIVATE_KEY, "", "") == false)
	{
		return false;
	}

	PmLogDebug("[%s, %d] Success", __FUNCTION__, __LINE__);
	return true;
}

bool TC_CreateKeyWithPassword()
{
	EVP_PKEY *pkey = NULL;

	const std::string outputKeyFilename = "keyWithPassword.pem";
	std::unique_ptr<OpensslRsaKeyWrapper> upOpenRsaPrivateKey(new OpensslRsaKeyWrapper());

	if(upOpenRsaPrivateKey->open(outputKeyFilename, 'w', FORMAT_PEM, 2048) == false)
	{
		return false;
	}

	pkey = upOpenRsaPrivateKey->getPkey();
	if(pkey == NULL)
	{
		PmLogError("[%s, %d]", __FUNCTION__, __LINE__);
		return false;
	}	

	//ret = upOpenRsaPrivateKey->write(pkey, PKEY_TYPE_T::PKEY_PRIVATE_KEY, "123456789", "AES-256-CBC");
	if(upOpenRsaPrivateKey->write(pkey, PKEY_TYPE_T::PKEY_PRIVATE_KEY, "123456789123456789", "AES-256-CBC") == false)
	{
		return false;
	}

	PmLogDebug("[%s, %d] Success", __FUNCTION__, __LINE__);
	return true;
}

bool TC_DecryptKey()
{
	const std::string inputKeyFilename = "keyWithPassword.pem";
	std::unique_ptr<OpensslRsaKeyWrapper> upOpenRsaPrivateKey(new OpensslRsaKeyWrapper());

	if(upOpenRsaPrivateKey->open(inputKeyFilename, 'r', FORMAT_PEM) == false)
	{
		PmLogError("[%s, %d]", __FUNCTION__, __LINE__);
		return false;
	}

	if(upOpenRsaPrivateKey->read(PKEY_TYPE_T::PKEY_PRIVATE_KEY, "123456789123456789") == false)
	{
		PmLogError("[%s, %d]", __FUNCTION__, __LINE__);
		return false;
	}

	PmLogDebug("[%s, %d] Success", __FUNCTION__, __LINE__);
	return true;
}

TEST(TCS_OpensslRasKeyWrapper, test_case_1)
{
	EXPECT_EQ(true, TC_CreateKeyWithoutPassword());
}

TEST(TCS_OpensslRasKeyWrapper, test_case_2)
{
	EXPECT_EQ(true, TC_CreateKeyWithPassword());
}

TEST(TCS_OpensslRasKeyWrapper, test_case_3)
{
	EXPECT_EQ(true, TC_DecryptKey());
}

int main(int argc, char **argv)
{
	::testing::InitGoogleTest(&argc, argv);
	return RUN_ALL_TESTS();
}