#include <string>
#include <memory>
#include "Log.hpp"
#include "OpensslConfWrapper.hpp"

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

	std::string inputConfigFile = "../scripts/root_openssl.cnf";
	std::unique_ptr<OpensslConfWrapper> upOpensslConfWrapper(new OpensslConfWrapper());
	upOpensslConfWrapper->open(inputConfigFile);
	entry = upOpensslConfWrapper->lookupEntry(BASE_SECTION, ENV_DEFAULT_CA);

	//str = upOpensslConfWrapper->getString(entry, STRING_MASK);
	//PmLogDebug("STRING_MASK : %s", str);

	//str = upOpensslConfWrapper->getString(entry, UTF8_IN);
	//PmLogDebug("UTF8_IN : %s", str);

	number = upOpensslConfWrapper->getNumber(entry, ENV_DEFAULT_DAYS);
	PmLogDebug("Expired Days : %lld", number);
}

int main()
{
	testConf();
	return 0;
}