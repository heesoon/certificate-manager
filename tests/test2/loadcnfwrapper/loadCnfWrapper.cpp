#include <iostream>
#include "loadCnfWrapper.hpp"

LoadCnfWrapper::LoadCnfWrapper()
{
    conf = NULL;
}

bool LoadCnfWrapper::loadConf(const std::string &inputKeyFilename)
{
    bool ret = false;
    CONF *tconf = NULL;
    BioWrapper bioWrapper;
    int i = 0;
    long errorline = -1;

    ret = bioWrapper.open(inputKeyFilename, 'r', FORMAT_TEXT);
    if(ret == false)
    {
        std::cout << "open bio error" << std::endl;
        return false;
    }

    BIO *key = bioWrapper.getBio();

    tconf = NCONF_new(NULL);

    i = NCONF_load_bio(tconf, key, &errorline);
    if(i == 0)
    {
        NCONF_free(tconf);
        return false;
    }

	i = CONF_modules_load(tconf, NULL, 0);
	if(i <= 0)
	{
		NCONF_free(tconf);
		return false;
	}

    conf = tconf;
    return true;
}

char* LoadCnfWrapper::lookupEntry(const std::string &section, const std::string &tag)
{
    char *entry = NULL;

    if(conf == NULL)
    {
        return NULL;
    }

    entry = NCONF_get_string(conf, section.c_str(), tag.c_str());
    if(entry == NULL)
    {
        return NULL;
    }

    return entry;
}

char* LoadCnfWrapper::getString(const std::string &section, const std::string &tag)
{
    char *s = NCONF_get_string(conf, section.c_str(), tag.c_str());

    if(s == NULL)
    {
        return NULL;
    }

    return s;
}

long LoadCnfWrapper::getNumber(const std::string &section, const std::string &tag)
{
    int ret = 0;
    long result = 0;
    
    ret = NCONF_get_number(conf, section.c_str(), tag.c_str(), &result);
    if(ret == 0)
    {
        result = 0;
        return result;
    }

    return result;
}

CONF* LoadCnfWrapper::getConf()
{
    return conf;
}

LoadCnfWrapper::~LoadCnfWrapper()
{
    NCONF_free(conf);
    std::cout << "~LoadCnfWrapper called.." << std::endl;
}