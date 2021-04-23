#include <string>
#include <openssl/conf.h>

class CnfWrapper
{
public:
    CnfWrapper();
    bool loadConf(const std::string &inputKeyFilename);
    char* lookupEntry(const std::string &section, const std::string &tag);
    char* getString(const std::string &section, const std::string &tag);
    long getNumber(const std::string &section, const std::string &tag);
	STACK_OF(CONF_VALUE)* getSection(const CONF *conf, const std::string &section);
    CONF* getConf();
    virtual ~CnfWrapper();
private:
    CONF *conf;
};