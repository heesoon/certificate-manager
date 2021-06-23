#include <string>
#include <memory>
#include <cstdlib>
#include "gtest/gtest.h"
#include "Log.hpp"
#include "OpensslCsrWrapper.hpp"
#include "OpensslBioWrapper.hpp"
#include "OpensslCaWrapper.hpp"

bool TC_MakeCsr()
{
	X509_REQ *x509Req = NULL;
	std::string outputFileName = "";
	std::string inputConfFileName = "";
	std::string inputPrivateKey = "";
	subject_t subject;


	std::string homeDir = getenv("HOME");
	if(homeDir.empty())
	{
		return false;
	}
	
	outputFileName = homeDir + "/ca/test/csr.pem";
	inputConfFileName = homeDir + "/ca/test/customer_openssl.cnf";
	inputPrivateKey = homeDir + "/ca/test/customer.key.pem";

	subject.commonName = "Customer Inc";
	subject.countryName = "KR";
	subject.stateOrProvinceName = "Seoul";
	subject.localityName = "Seoul";
	subject.organizationName = "Customer Inc R&D";
	subject.emailAddress = "customer@rnd.com";

	std::unique_ptr<OpensslCsrWrapper> upOpenCsr(new OpensslCsrWrapper());
	if(upOpenCsr == nullptr)
	{
		PmLogError("[%s, %d]", __FUNCTION__, __LINE__);
		return false;
	}

	if(upOpenCsr->open(outputFileName, 'w', FORMAT_PEM) == false)
	{
		PmLogError("[%s, %d]", __FUNCTION__, __LINE__);
		return false;
	}

	if(upOpenCsr->makeCsr(inputConfFileName, inputPrivateKey, subject) == false)
	{
		PmLogError("[%s, %d]", __FUNCTION__, __LINE__);
		return false;
	}

	x509Req = upOpenCsr->getX509Req();
	if(x509Req == NULL)
	{
		PmLogError("[%s, %d]", __FUNCTION__, __LINE__);
		return false;
	}

	if(upOpenCsr->write(x509Req) == false)
	{
		PmLogError("[%s, %d]", __FUNCTION__, __LINE__);
		return false;
	}

	PmLogDebug("[%s, %d] Success", __FUNCTION__, __LINE__);

	//openssl req -noout -text -in csr.pem
	return true;
}

bool TC_SignByCa()
{
	X509 *x509 = NULL;
	std::string outputCertFile = "";
	std::string inputConfigFile = "";
	std::string inputCsrFile = "";

	std::string homeDir = getenv("HOME");
	if(homeDir.empty())
	{
		return false;
	}

	std::unique_ptr<OpensslCaWrapper> upOpenCa(new OpensslCaWrapper());

	outputCertFile = homeDir + "/ca/test/customer.cert";
	inputConfigFile = homeDir + "/ca/test/customer_openssl.cnf";
	inputCsrFile = homeDir + "/ca/test/csr.pem";
	
	if(upOpenCa->open(outputCertFile, 'w', FORMAT_PEM) == false)
	{
		PmLogError("[%s, %d]", __FUNCTION__, __LINE__);
		return false;
	}

	if(upOpenCa->generateCertSignedByCa(inputConfigFile, inputCsrFile) == false)
	{
		PmLogError("[%s, %d]", __FUNCTION__, __LINE__);
		return false;
	}

	x509 = upOpenCa->getX509();
	if(x509 == NULL)
	{
		PmLogError("[%s, %d]", __FUNCTION__, __LINE__);
		return false;
	}

	if(upOpenCa->write(x509) == false)
	{
		PmLogError("[%s, %d]", __FUNCTION__, __LINE__);
		return false;
	}

	PmLogDebug("[%s, %d] Success", __FUNCTION__, __LINE__);
	return true;
}

bool TC_Verify()
{
	std::string inputCertFile = "";
	std::string inputCaChainFile = "";

	std::string homeDir = getenv("HOME");
	if(homeDir.empty())
	{
		return false;
	}
	
	std::unique_ptr<OpensslCaWrapper> upOpenCa(new OpensslCaWrapper());

	inputCertFile = homeDir + "/ca/test/customer.cert";
	inputCaChainFile = homeDir + "/ca/test/ca-chain.cert.pem";

	if(upOpenCa->verifyByCa(inputCaChainFile, inputCertFile) == false)
	{
		PmLogError("[%s, %d]", __FUNCTION__, __LINE__);
		return false;
	}

	PmLogDebug("[%s, %d] Success", __FUNCTION__, __LINE__);
	return true;
}

TEST(TCS_OpensslCaWrapper, test_case_1)
{
	EXPECT_EQ(true, TC_MakeCsr());
}

TEST(TCS_OpensslCaWrapper, test_case_2)
{
	EXPECT_EQ(true, TC_SignByCa());
}

TEST(TCS_OpensslCaWrapper, test_case_3)
{
	EXPECT_EQ(true, TC_Verify());
}

int main(int argc, char **argv)
{
	::testing::InitGoogleTest(&argc, argv);
	return RUN_ALL_TESTS();
}