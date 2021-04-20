#include <iostream>
#include <cstring>
#include "bioWrapper.hpp"
#include "CsrWrapper.hpp"
#include "CnfWrapper.hpp"
#include <openssl/x509v3.h>

#define REQ_BASE_SECTION            "req"

#define BITS                        "default_bits"
#define KEYFILE                     "default_keyfile"
#define PROMPT                      "prompt"
#define DISTINGUISHED_NAME          "distinguished_name"
#define ATTRIBUTES                  "attributes"
#define V3_EXTENSIONS               "x509_extensions"
#define REQ_EXTENSIONS              "req_extensions"
#define STRING_MASK                 "string_mask"
#define UTF8_IN                     "utf8"
#define DEFAULT_MD                  "default_md"

CsrWrapper::CsrWrapper()
{
    x509ReadReq = NULL;
    x509WriteReq = NULL;
}

bool CsrWrapper::openCert()
{
    if(x509WriteReq != NULL)
    {
        return false;     
    }

    x509WriteReq = X509_REQ_new();
}

bool CsrWrapper::readCsr(const std::string &inputFileName, int format)
{
    bool ret = false;
    BIO *csr = NULL;
    X509_REQ *req = NULL;
    BioWrapper bioWrapper;

    if(inputFileName.empty() == true)
    {
        return false;
    }

    ret = bioWrapper.open(inputFileName, 'r', format);
    if(ret == false)
    {
        std::cout << "open bio error" << std::endl;
        return false;
    }

    csr = bioWrapper.getBio();

    if(format == FORMAT_ASN1)
    {
        req = d2i_X509_REQ_bio(csr, NULL);
    }
    else if(format == FORMAT_PEM)
    {
        req = PEM_read_bio_X509_REQ(csr, NULL, NULL, NULL);
    }
    else
    {
        std::cout << "currently not support" << std::endl;
        return false;
    }

    if(req == NULL)
    {
        return false;
    }

    x509ReadReq = req;
    return true;
}

bool CsrWrapper::writeCsr(const std::string &outputFileName, int format)
{
    bool ret = false;
    BIO *csr = NULL;
    BioWrapper bioWrapper;

    if(outputFileName.empty() == true)
    {
        return false;
    }

    ret = bioWrapper.open(outputFileName, 'w', format);
    if(ret == false)
    {
        std::cout << "open bio error" << std::endl;
        return false;
    }

    csr = bioWrapper.getBio();

    if(format == FORMAT_ASN1)
    {
        ret = i2d_X509_REQ_bio(csr, x509WriteReq);
    }
    else if(format == FORMAT_PEM)
    {
        ret = PEM_write_bio_X509_REQ(csr, x509WriteReq);
        //ret = PEM_write_bio_X509_REQ_NEW(csr, x509);
    }
    else
    {
        std::cout << "currently not support" << std::endl;
        return false;
    }

    if(ret == 0)
    {
        return false;
    }

    return true;
}

bool CsrWrapper::makeCsr(const std::string &inputKeyFilename, const std::string &inputCnfFilename, const subject_t &subject)
{
    int ret = 0;
    CnfWrapper cnfwrapper;
    char *cnfData = NULL;
    const EVP_MD *md_alg = NULL;
    X509_NAME *x509_name = NULL;
    unsigned long chtype = MBSTRING_ASC;

	if(inputKeyFilename.empty() || inputCnfFilename.empty())
	{
		return false;
	}

    cnfwrapper.loadConf(inputCnfFilename);

    // 1. get default md from configuration file
    cnfData = cnfwrapper.getString(REQ_BASE_SECTION, DEFAULT_MD);
    if(cnfData == NULL)
    {
        return false;
    }

	md_alg = EVP_get_digestbyname(cnfData);
	if(md_alg == NULL)
	{
		return false;
	}

    // 2. get string mask from configuration file
    cnfData = cnfwrapper.getString(REQ_BASE_SECTION, STRING_MASK);
    if(cnfData == NULL)
    {
        return false;
    }

    ret = ASN1_STRING_set_default_mask_asc(cnfData);
    if(ret == 0)
    {
        return false;
    }

    // 3. get character type from configuration file
    cnfData = cnfwrapper.getString(REQ_BASE_SECTION, UTF8_IN);
    if(cnfData == NULL)
    {
        return false;
    }

    if(std::strcmp(cnfData, "yes") == 0)
    {
        chtype = MBSTRING_UTF8;
    }

    // 4. get request extension from configuration file
    cnfData = cnfwrapper.getString(REQ_BASE_SECTION, REQ_EXTENSIONS);
    if(cnfData != NULL)
    {
        /* Check syntax of file */
        X509V3_CTX ctx;
        CONF* conf = cnfwrapper.getConf();
        X509V3_set_ctx_test(&ctx);
        X509V3_set_nconf(&ctx, conf);
        if(!X509V3_EXT_add_nconf(conf, &ctx, cnfData, NULL))
        {
            return false;
        }
    }

    // 5. TO DO. if need to add more value from configuration file

    // 6. set subject from input
    x509_name = X509_NAME_new();
    if(x509_name == NULL)
    {
        return false;
    }

    char *p = subject.commonName.c_str();
	ret = X509_NAME_add_entry_by_txt(x509_name, "commonName", chtype, (unsigned char*)p, -1, -1, 0);
	if(ret == 0)
	{
		X509_NAME_free(x509_name);
		return false;
	}
#if 0
	ret = X509_NAME_add_entry_by_txt(up_x509_name.get(), "countryName", MBSTRING_ASC, reinterpret_cast<unsigned char*>(subject->countryName), -1, -1, 0);
	if(ret == 0)
	{
		LOGE("X509_NAME_add_entry_by_txt");
		return false;
	}

	ret = X509_NAME_add_entry_by_txt(up_x509_name.get(), "stateOrProvinceName", MBSTRING_ASC, reinterpret_cast<unsigned char*>(subject->stateOrProvinceName), -1, -1, 0);
	if(ret == 0)
	{
		LOGE("X509_NAME_add_entry_by_txt");
		return false;
	}

	ret = X509_NAME_add_entry_by_txt(up_x509_name.get(), "localityName", MBSTRING_ASC, reinterpret_cast<unsigned char*>(subject->localityName), -1, -1, 0);
	if(ret == 0)
	{
		LOGE("X509_NAME_add_entry_by_txt");
		return false;
	}

	ret = X509_NAME_add_entry_by_txt(up_x509_name.get(), "organizationName", MBSTRING_ASC, reinterpret_cast<unsigned char*>(subject->organizationName), -1, -1, 0);
	if(ret == 0)
	{
		LOGE("X509_NAME_add_entry_by_txt");
		return false;
	}

	ret = X509_NAME_add_entry_by_txt(up_x509_name.get(), "emailAddress", MBSTRING_ASC, reinterpret_cast<unsigned char*>(subject->emailAddress), -1, -1, 0);
	if(ret == 0)
	{
		LOGE("X509_NAME_add_entry_by_txt");
		return false;
	}
#endif    
}

X509_REQ* CsrWrapper::getX509ReadReq()
{
    return x509ReadReq;
}

X509_REQ* CsrWrapper::getX509WriteReq()
{
    return x509WriteReq;
}

CsrWrapper::~CsrWrapper()
{
    X509_REQ_free(x509ReadReq);
    X509_REQ_free(x509WriteReq);
    std::cout << "~CsrWrapper called.." << std::endl;
}