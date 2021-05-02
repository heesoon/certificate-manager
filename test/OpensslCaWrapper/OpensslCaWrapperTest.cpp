#include <string>
#include <memory>
#include "Log.hpp"
#include "OpensslBioWrapper.hpp"
#include "OpensslCaWrapper.hpp"

void testSignByCa()
{
	bool ret = false;
	X509 *x509 = NULL;
	//const std::string outputCertFile = "../test/OpensslCaWrapper/customer.cert";
	const std::string outputCertFile = "customer.cert";
	const std::string inputConfigFile = "../scripts/customer_openssl.cnf";
	const std::string inputCsrFile = "../test/OpensslCaWrapper/csr.pem";
	std::unique_ptr<OpensslCaWrapper> upOpenCa(new OpensslCaWrapper());
	
	ret = upOpenCa->open(outputCertFile, 'w', FORMAT_PEM);
	if(ret == false)
	{
		PmLogError("[%s, %d]", __FUNCTION__, __LINE__);
		return;
	}

	ret = upOpenCa->generateCertSignedByCa(inputConfigFile, inputCsrFile);
	if(ret == false)
	{
		PmLogError("[%s, %d]", __FUNCTION__, __LINE__);
		return;
	}

	x509 = upOpenCa->getX509();
	if(x509 == NULL)
	{
		PmLogError("[%s, %d]", __FUNCTION__, __LINE__);
		return;
	}

	ret = upOpenCa->write(x509);
	if(ret == false)
	{
		PmLogError("[%s, %d]", __FUNCTION__, __LINE__);
		return;
	}

	PmLogDebug("[%s, %d] Success", __FUNCTION__, __LINE__);
}

void testVerify()
{
	bool ret = false;
	//const std::string inputCertFile = "../test/OpensslCaWrapper/customer.cert";
	const std::string inputCertFile = "customer.cert";
	const std::string inputCaChainFile = "../test/OpensslCaWrapper/ca-chain.cert.pem";
	std::unique_ptr<OpensslCaWrapper> upOpenCa(new OpensslCaWrapper());
	
	ret = upOpenCa->verifyByCa(inputCaChainFile, inputCertFile);
	if(ret == false)
	{
		PmLogError("[%s, %d]", __FUNCTION__, __LINE__);
		return;
	}

	PmLogDebug("[%s, %d] Success", __FUNCTION__, __LINE__);
}

int main()
{
	testSignByCa();
	testVerify();
	return 0;
}