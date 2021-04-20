#include <iostream>
#include <string>
#include <memory>
#include "CnfWrapper.hpp"

#define BASE_SECTION		"ca"
#define ENV_DEFAULT_CA		"default_ca"
#define STRING_MASK			"string_mask"
#define UTF8_IN				"utf8"
#define ENV_DEFAULT_DAYS	"default_days"

void testConf()
{
	char *entry = NULL;
	char *str = NULL;
	long number = 0;

	std::string input_config_filename = "/home/hskim/share/certificate-manager/tests/test3/scripts/customer_openssl.cnf";
	std::unique_ptr<CnfWrapper> upCnfWrapper(new CnfWrapper());
	upCnfWrapper->loadConf(input_config_filename);
	entry = upCnfWrapper->lookupEntry(BASE_SECTION, ENV_DEFAULT_CA);

	str = upCnfWrapper->getString(entry, STRING_MASK);
	std::cout << "STRING_MASK : " << str << std::endl;

	str = upCnfWrapper->getString(entry, UTF8_IN);
	std::cout << "UTF8_IN : " << str << std::endl;

	number = upCnfWrapper->getNumber(entry, ENV_DEFAULT_DAYS);
	std::cout << "ENV_DEFAULT_DAYS : " << number << std::endl;	
}

int main()
{
	testConf();
	return 0;
}