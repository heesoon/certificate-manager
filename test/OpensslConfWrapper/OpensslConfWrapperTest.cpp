#include <string>
#include <memory>
#include <cstdlib>
#include "Log.hpp"
#include "gtest/gtest.h"
#include "OpensslConfWrapper.hpp"

#define BASE_SECTION		"ca"
#define ENV_DEFAULT_CA		"default_ca"
#define STRING_MASK			"string_mask"
#define DEFAULT_MD			"default_md"
#define UTF8_IN				"utf8"
#define ENV_DEFAULT_DAYS	"default_days"

bool TC_ReadConfDefaultMd()
{	
	char *entry = NULL;
	std::string str = "";
	std::string inputConfigFile = "";
	std::string homeDir = getenv("HOME");
	if(homeDir.empty())
	{
		return false;
	}

	std::unique_ptr<OpensslConfWrapper> upOpensslConfWrapper(new OpensslConfWrapper());
	inputConfigFile = homeDir + "/ca/root/openssl.cnf";
	upOpensslConfWrapper->open(inputConfigFile);
	entry = upOpensslConfWrapper->lookupEntry(BASE_SECTION, ENV_DEFAULT_CA);

	str = upOpensslConfWrapper->getString(entry, DEFAULT_MD);
	if(str == "sha512")
	{
		return true;
	}

	return false;
}

bool TC_ReadConfDefaulDays()
{	
	char *entry = NULL;
	std::string inputConfigFile = "";
	long num = 0;

	std::string homeDir = getenv("HOME");
	if(homeDir.empty())
	{
		return false;
	}

	std::unique_ptr<OpensslConfWrapper> upOpensslConfWrapper(new OpensslConfWrapper());
	
	inputConfigFile = homeDir + "/ca/root/openssl.cnf";
	upOpensslConfWrapper->open(inputConfigFile);
	entry = upOpensslConfWrapper->lookupEntry(BASE_SECTION, ENV_DEFAULT_CA);

	num = upOpensslConfWrapper->getNumber(entry, ENV_DEFAULT_DAYS);
	//PmLogDebug("Expired Days : %lld", num);
	if(num == 3750)
	{
		return true;
	}

	return false;
}

TEST(TCS_OpensslConfWrapper, test_case_1)
{
	//EXPECT_STREQ("sha512", TC_ReadConfDefaultMd());
	EXPECT_EQ(true, TC_ReadConfDefaultMd());
}

TEST(TCS_OpensslConfWrapper, test_case_2)
{
	EXPECT_EQ(true, TC_ReadConfDefaulDays());
}

int main(int argc, char **argv)
{
	::testing::InitGoogleTest(&argc, argv);
	return RUN_ALL_TESTS();
}