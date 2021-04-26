#include "Log.hpp"
#include "OpensslBioWrapper.hpp"
#include "OpensslConfWrapper.hpp"

OpensslConfWrapper::OpensslConfWrapper()
{
    conf = NULL;
}

bool OpensslConfWrapper::open(const std::string &inputConfFilename)
{
	int ret = 0;
    long errorline = -1;	
    CONF *tconf = NULL;
	BIO *bio = NULL;

    OpensslBioWrapper opensslBioWrapper;
    if(opensslBioWrapper.open(inputConfFilename, 'r', FORMAT_TEXT) == false)
    {
        PmLogError("[%s, %d] Bio Open Fail", __FUNCTION__, __LINE__);
        goto error;
    }

    tconf = NCONF_new(NULL);
	if(tconf == NULL)
	{
        PmLogError("[%s, %d] NCONF_new Fail", __FUNCTION__, __LINE__);
        goto error;
	}

    bio = opensslBioWrapper.getBio();
    ret = NCONF_load_bio(tconf, bio, &errorline);
    if(ret == 0)
    {
        PmLogError("[%s, %d] NCONF_load_bio fail", __FUNCTION__, __LINE__);
        goto error;
    }

	ret = CONF_modules_load(tconf, NULL, 0);
	if(ret <= 0)
	{
        PmLogError("[%s, %d] CONF_modules_load fail", __FUNCTION__, __LINE__);
        goto error;
	}

	conf = tconf;
	return true;

error:
	NCONF_free(tconf);
    return false;
}

char* OpensslConfWrapper::lookupEntry(const std::string &section, const std::string &tag)
{
    char *entry = NULL;

    if(conf == NULL)
    {
		PmLogError("[%s, %d] CONF is NULL", __FUNCTION__, __LINE__);
        return NULL;
    }

    entry = NCONF_get_string(conf, section.c_str(), tag.c_str());
    if(entry == NULL)
    {
		PmLogError("[%s, %d] entry is NULL", __FUNCTION__, __LINE__);
        return NULL;
    }

    return entry;
}

char* OpensslConfWrapper::getString(const std::string &section, const std::string &tag)
{
    char *s = NCONF_get_string(conf, section.c_str(), tag.c_str());

    if(s == NULL)
    {
		PmLogError("[%s, %d] NCONF_get_string is NULL", __FUNCTION__, __LINE__);
        return NULL;
    }

    return s;
}

long OpensslConfWrapper::getNumber(const std::string &section, const std::string &tag)
{
    int ret = 0;
    long result = 0;
    
    ret = NCONF_get_number(conf, section.c_str(), tag.c_str(), &result);
    if(ret == 0)
    {
		PmLogError("[%s, %d] NCONF_get_number is fail", __FUNCTION__, __LINE__);
        result = 0;
        return result;
    }

    return result;
}

STACK_OF(CONF_VALUE)* OpensslConfWrapper::getSection(const CONF *conf, const std::string &section)
{
	return NCONF_get_section(conf, section.c_str());
}

CONF* OpensslConfWrapper::getConf()
{
    return conf;
}

bool OpensslConfWrapper::close()
{
	NCONF_free(conf);
	conf = NULL;

	return true;
}

OpensslConfWrapper::~OpensslConfWrapper()
{
    NCONF_free(conf);
    PmLogDebug("[%s,%d]", __FUNCTION__, __LINE__);
}