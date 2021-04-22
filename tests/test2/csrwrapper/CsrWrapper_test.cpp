#include <iostream>
#include <string>
#include <memory>
#include "bioWrapper.hpp"
#include "CsrWrapper.hpp"

void testGenerateCsr()
{
	bool ret = false;
	CsrWrapper cswrapper;

	std::string input_config_filename = "/home/hskim/share/certificate-manager/tests/test3/scripts/customer_openssl.cnf";
	std::string input_privatekey_filename = "test_key.pem";
	std::string output_csr_filename = "csr.pem";

	subject_t subject;
	subject.commonName = "Customer Inc";
	subject.countryName = "KR";
	subject.stateOrProvinceName = "Seoul";
	subject.localityName = "Seoul";
	subject.organizationName = "Customer Inc R&D";
	subject.emailAddress = "customer@rnd.com";

	ret = cswrapper.makeCsr(input_privatekey_filename, input_config_filename, subject);
	if(ret == false)
	{
		return;
	}

	ret = cswrapper.writeCsr(output_csr_filename, FORMAT_PEM);
	if(ret == false)
	{
		return;
	}

	std::cout << "Success" << std::endl;
}

int main()
{
	testGenerateCsr();
	return 0;
}