#include <iostream>
#include <string>
#include <memory>
#include "bioWrapper.hpp"
#include "CaWrapper.hpp"

void testCa()
{
	bool ret = false;
	CaWrapper cawrapper;
	std::string input_config_filename = "/home/hskim/share/certificate-manager/tests/test3/scripts/customer_openssl.cnf";
	std::string input_csr_filename = "/home/hskim/certificates/customer/csr/customer.csr.pem";
	std::string output_certificate_filename = "customer_certificate.pem";

	ret = cawrapper.ca(input_config_filename, input_csr_filename);
	if(ret == false)
	{
		return;
	}

	std::cout << "Success" << std::endl;
}

int main()
{
	testCa();
	return 0;
}