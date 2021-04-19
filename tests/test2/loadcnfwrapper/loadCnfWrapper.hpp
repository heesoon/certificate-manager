#include "bioWrapper.hpp"
#include <string>
#include <openssl/conf.h>

class LoadCnfWrapper
{
public:
    LoadCnfWrapper();
    bool loadConf(const std::string &inputKeyFilename);
    char* lookupEntry(const std::string &section, const std::string &tag);
    char* getString(const std::string &section, const std::string &tag);
    long getNumber(const std::string &section, const std::string &tag);
    CONF* getConf();
    virtual ~LoadCnfWrapper();
private:
    CONF *conf;
};