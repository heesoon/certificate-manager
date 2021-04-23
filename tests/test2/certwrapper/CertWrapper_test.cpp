#include <iostream>
#include <string>
#include <memory>
#include "bioWrapper.hpp"
#include "CertWrapper.hpp"

void testCert()
{
	std::string input_certificate_filename = "customer_certificate.pem";
	std::unique_ptr<CertWrapper> upCertWrapper(new CertWrapper);
	upCertWrapper->readCert(input_certificate_filename, FORMAT_PEM);
}

int main()
{
	testCert();
	return 0;
}