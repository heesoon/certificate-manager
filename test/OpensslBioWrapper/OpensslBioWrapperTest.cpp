#include <iostream>
#include <string>
#include <memory>
#include "Log.hpp"
#include "OpensslBioWrapper.hpp"

void test_OpensslBioWrapper_text()
{
	bool ret = false;

	// configuration file open based on text
	std::string inputConfigFile = "../scripts/root_openssl.cnf";
	std::unique_ptr<OpensslBioWrapper> bioWrapperCnf(new OpensslBioWrapper);

	ret = bioWrapperCnf->openBio(inputConfigFile.c_str(), 'r', FORMAT_TEXT);
	if(ret == false)
	{
		PmLogError("[%s,%d]", __FUNCTION__, __LINE__);
		return;
	}

	PmLogDebug("[%s,%d] Success", __FUNCTION__, __LINE__);
}

#if 0
void test_OpensslBioWrapper_pem()
{
	bool ret = false;

	// pivate key file open based on pem format
	std::string input_key_filename = "/home/hskim/certificates/customer/csr/customer.csr.pem";
	std::unique_ptr<OpensslBioWrapper> bioWrapperKey(new OpensslBioWrapper);

	ret = bioWrapperKey->open(input_key_filename.c_str(), 'r', FORMAT_PEM);
	if(ret == false)
	{
		PmLogError("[%s,%d]", __FUNCTION__, __LINE__);
		return;
	}

	PmLogDebug("[%s,%d] Success", __FUNCTION__, __LINE__);
}
#endif

int main()
{
	test_OpensslBioWrapper_text();
	//test_OpensslBioWrapper_pem();
	return 0;
}