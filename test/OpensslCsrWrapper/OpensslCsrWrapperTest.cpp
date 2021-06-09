#include <string>
#include <memory>
#include <cstdlib>
#include "gtest/gtest.h"
#include "Log.hpp"
#include "OpensslCsrWrapper.hpp"

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
	inputConfFileName = homeDir + "/ca/customer/openssl.cnf";
	inputPrivateKey = homeDir + "/ca/test/privatekey.pem";

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

TEST(TCS_OpensslCsrWrapper, test_case_1)
{
	EXPECT_EQ(true, TC_MakeCsr());
}

int main(int argc, char **argv)
{
	::testing::InitGoogleTest(&argc, argv);
	return RUN_ALL_TESTS();
}