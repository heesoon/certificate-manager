#ifndef OPENSSLCONFWRAPPER_HPP_INCLUDED
#define OPENSSLCONFWRAPPER_HPP_INCLUDED

#include <string>
#include <memory>
#include <openssl/conf.h>

class OpensslConfWrapper
{
public:
    OpensslConfWrapper();
    virtual ~OpensslConfWrapper();
    bool open(const std::string &inputConfFilename);
    CONF* getConf();
    void close();
    char* lookupEntry(const std::string &section, const std::string &tag);
    char* getString(const std::string &section, const std::string &tag);
    long getNumber(const std::string &section, const std::string &tag);
	STACK_OF(CONF_VALUE)* getSection(const CONF *conf, const std::string &section);

private:
    CONF *conf;
};
#endif