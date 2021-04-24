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
	std::string output_certificate_filename = "customer.cert";

	ret = cawrapper.init();
	if(ret == false)
	{
		return;
	}

	ret = cawrapper.ca(input_config_filename, input_csr_filename);
	if(ret == false)
	{
		return;
	}

	ret = cawrapper.saveSignedCert(output_certificate_filename, FORMAT_PEM);
	if(ret == false)
	{
		return;
	}

	std::cout << "Signing Success" << std::endl;
}

void testVerify()
{
	bool ret = false;
	CaWrapper cawrapper;
	std::string input_ca_chain_file = "/home/hskim/certificates/intermediate/certs/ca-chain.cert.pem";
	std::string input_certificate_file = "customer.cert";

	ret = cawrapper.verify(input_ca_chain_file.c_str(), input_certificate_file.c_str());
	if(ret == false)
	{
		return;
	}

	std::cout << "Verify Success" << std::endl;
}

int main()
{
	testCa();
	testVerify();
	return 0;
}