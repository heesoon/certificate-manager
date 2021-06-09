#include <string>
#include <cstdlib>
#include <memory>
#include "gtest/gtest.h"
#include "OpensslBioWrapper.hpp"

bool TC_OpenBioFile()
{
	std::string inputConfigFile = "";
	std::string homeDir = getenv("HOME");
	if(homeDir.empty())
	{
		return false;
	}

	inputConfigFile = homeDir + "/ca/root/openssl.cnf";
	std::unique_ptr<OpensslBioWrapper> bioWrapperCnf(new OpensslBioWrapper);

	if(bioWrapperCnf->open(inputConfigFile.c_str(), 'r', FORMAT_TEXT) == false)
	{
		return false;
	}

	return true;
}

TEST(TCS_OpensslBioWrapper, test_case_1)
{
	EXPECT_EQ(true, TC_OpenBioFile());
}

int main(int argc, char **argv)
{
	::testing::InitGoogleTest(&argc, argv);
	return RUN_ALL_TESTS();
}