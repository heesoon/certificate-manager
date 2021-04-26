#include <iostream>
#include <string>
#include <memory>
#include "OpensslBioWrapper.hpp"

void test_OpensslBioWrapper_text()
{
	bool ret = false;

	// configuration file open based on text
	std::string input_config_filename = "/home/hskim/share/certificate-manager/tests/test3/scripts/customer_openssl.cnf";
	std::unique_ptr<OpensslBioWrapper> bioWrapperCnf(new OpensslBioWrapper);

	ret = bioWrapperCnf->open(input_config_filename.c_str(), 'r', FORMAT_TEXT);
	if(ret == false)
	{
		std::cout << "bio open error" << std::endl;
		return;
	}
	std::cout << "Success open configuration file based on TEXT" << std::endl;
}

void test_OpensslBioWrapper_pem()
{
	bool ret = false;

	// pivate key file open based on pem format
	std::string input_key_filename = "/home/hskim/certificates/customer/csr/customer.csr.pem";
	std::unique_ptr<OpensslBioWrapper> bioWrapperKey(new OpensslBioWrapper);

	ret = bioWrapperKey->open(input_key_filename.c_str(), 'r', FORMAT_PEM);
	if(ret == false)
	{
		std::cout << "bio open error" << std::endl;
		return;
	}	
	std::cout << "Success open key file based on PEM" << std::endl;
}

int main()
{
	test_OpensslBioWrapper_text();
	test_OpensslBioWrapper_pem();
	return 0;
}