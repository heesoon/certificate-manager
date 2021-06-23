#include <string>
#include <memory>
#include <cstdlib>
#include "gtest/gtest.h"
#include "Log.hpp"
#include "OpensslBioWrapper.hpp"
#include "OpensslCertWrapper.hpp"

bool TC_CertReadTest()
{
	std::string filename = "";
	std::string homeDir = getenv("HOME");
	if(homeDir.empty())
	{
		return false;
	}
	
	filename = homeDir + "/ca/root/certs/ca.cert.pem";

	std::unique_ptr<OpensslCertWrapper> upOpenCert(new OpensslCertWrapper());

	if(upOpenCert->open(filename, 'r', FORMAT_PEM) == false)
	{
		return false;
	}

	if(upOpenCert->read() == false)
	{
		return false;
	}

	//PmLogDebug("[%s, %d] Success", __FUNCTION__, __LINE__);
	return true;
}


TEST(TCS_OpensslCertWrapper, test_case_1)
{
	EXPECT_EQ(true, TC_CertReadTest());
}

int main(int argc, char **argv)
{
	::testing::InitGoogleTest(&argc, argv);
	return RUN_ALL_TESTS();
}