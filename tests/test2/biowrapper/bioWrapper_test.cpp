#include <iostream>
#include <string>
#include <memory>
#include "bioWrapper.hpp"

void test_biowrapper_text()
{
	bool ret = false;

	// configuration file open based on text
	std::string input_config_filename = "/home/hskim/share/certificate-manager/tests/test3/scripts/customer_openssl.cnf";
	std::unique_ptr<BioWrapper> bioWrapperCnf(new BioWrapper);

	ret = bioWrapperCnf->open(input_config_filename.c_str(), 'r', FORMAT_TEXT);
	if(ret == false)
	{
		std::cout << "bio open error" << std::endl;
		return;
	}
	std::cout << "Success open configuration file based on TEXT" << std::endl;
}

void test_biowrapper_pem()
{
	bool ret = false;

	// pivate key file open based on pem format
	std::string input_key_filename = "/home/hskim/certificates/customer/csr/customer.csr.pem";
	std::unique_ptr<BioWrapper> bioWrapperKey(new BioWrapper);

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
	test_biowrapper_text();
	test_biowrapper_pem();
	return 0;
}