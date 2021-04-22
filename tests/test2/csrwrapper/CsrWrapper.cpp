#include <iostream>
#include <cstring>
#include "bioWrapper.hpp"
#include "CsrWrapper.hpp"
#include "KeyWrapper.hpp"
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
    KeyWrapper keywrapper;
    char *cnfData = NULL;
    const EVP_MD *evpMd = NULL;
    X509_NAME *x509_name = NULL;
    EVP_PKEY *evpKey = NULL;
    EVP_PKEY *tpubkey = NULL;
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

	evpMd = EVP_get_digestbyname(cnfData);
	if(evpMd == NULL)
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

	ret = X509_NAME_add_entry_by_txt(x509_name, "commonName", chtype, reinterpret_cast<const unsigned char*>(subject.countryName.c_str()), -1, -1, 0);
	if(ret == 0)
	{
		X509_NAME_free(x509_name);
		return false;
	}

	ret = X509_NAME_add_entry_by_txt(x509_name, "countryName", chtype, reinterpret_cast<const unsigned char*>(subject.countryName.c_str()), -1, -1, 0);
	if(ret == 0)
	{
		X509_NAME_free(x509_name);
		return false;
	}

	ret = X509_NAME_add_entry_by_txt(x509_name, "stateOrProvinceName", chtype, reinterpret_cast<const unsigned char*>(subject.stateOrProvinceName.c_str()), -1, -1, 0);
	if(ret == 0)
	{
		X509_NAME_free(x509_name);
		return false;
	}

	ret = X509_NAME_add_entry_by_txt(x509_name, "localityName", chtype, reinterpret_cast<const unsigned char*>(subject.localityName.c_str()), -1, -1, 0);
	if(ret == 0)
	{
		X509_NAME_free(x509_name);
		return false;
	}

	ret = X509_NAME_add_entry_by_txt(x509_name, "organizationName", chtype, reinterpret_cast<const unsigned char*>(subject.organizationName.c_str()), -1, -1, 0);
	if(ret == 0)
	{
		X509_NAME_free(x509_name);
		return false;
	}

	ret = X509_NAME_add_entry_by_txt(x509_name, "emailAddress", chtype, reinterpret_cast<const unsigned char*>(subject.emailAddress.c_str()), -1, -1, 0);
	if(ret == 0)
	{
		X509_NAME_free(x509_name);
		return false;
	}

    // 7. read public key
    if(keywrapper.loadPrivateKey(inputKeyFilename, FORMAT_PEM) == false)
    {
        X509_NAME_free(x509_name);
        return false;
    }

    // 8. build X509_REQ structure
    x509WriteReq = X509_REQ_new();
  	if(x509WriteReq == NULL)
	{
		X509_NAME_free(x509_name);
		return false;
	}

	// 8.1. setting req revsion. currently there is only version 1
	ret = X509_REQ_set_version(x509WriteReq, 0L);
	if(ret == 0)
	{
		X509_NAME_free(x509_name);
		return false;
	}

	// 8.2. setting subject to req
	ret = X509_REQ_set_subject_name(x509WriteReq, x509_name);
	if(ret == 0)
	{
		X509_NAME_free(x509_name);
		return false;
	}

    // 8.3. setting subject to req
    evpKey = keywrapper.getEvpPrivateKey();
	ret = X509_REQ_set_pubkey(x509WriteReq, evpKey);
	if(ret == 0)
	{
		X509_NAME_free(x509_name);
		return false;
	}

    // 8.4. signing
	ret = X509_REQ_sign(x509WriteReq, evpKey, evpMd);
	if(ret == 0)
	{
		X509_NAME_free(x509_name);
		return false;
	}

    // 8.5. req verify
	tpubkey = evpKey;
	if(tpubkey == NULL)
	{
		tpubkey = X509_REQ_get0_pubkey(x509WriteReq);
		if(tpubkey == NULL)
		{
			X509_NAME_free(x509_name);
			return false;
		}
	}

	ret = X509_REQ_verify(x509WriteReq, tpubkey);
	if(ret <= 0)
	{
		X509_NAME_free(x509_name);
		return false;
	}
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