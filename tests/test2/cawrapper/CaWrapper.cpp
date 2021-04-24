#include <iostream>
#include <memory>
#include <cstring>
#include "bioWrapper.hpp"
#include "CsrWrapper.hpp"
#include "KeyWrapper.hpp"
#include "CnfWrapper.hpp"
#include "CaWrapper.hpp"
#include "CertWrapper.hpp"
#include <openssl/x509.h>
#include <openssl/x509v3.h>

auto delRawPtrBN = [](BIGNUM *bn)
{
	BN_free(bn);
};
using unique_ptr_bn_type_t = std::unique_ptr<BIGNUM, decltype(delRawPtrBN)>;

CaWrapper::CaWrapper()
{
    X509 *x509 = NULL;
}

bool CaWrapper::rand_serial(BIGNUM *b, ASN1_INTEGER *ai)
{
    bool ret = false;
    BIGNUM *btmp;

    btmp = b == NULL ? BN_new() : b;
    if(btmp == NULL)
    {
        return false;
    }

    if(!BN_rand(btmp, SERIAL_RAND_BITS, BN_RAND_TOP_ANY, BN_RAND_BOTTOM_ANY))
    {
        goto error;
    }

    if(ai && !BN_to_ASN1_INTEGER(btmp, ai))
    {
        goto error; 
    }

    ret = true;

error:

    if(btmp != b)
    {
        BN_free(btmp);
    }

    return ret;
}

BIGNUM* CaWrapper::load_serial(const char *serialfile, int create, ASN1_INTEGER **retai)
{
    BIO *in = NULL;
    BIGNUM *ret = NULL;
    char buf[1024];
    ASN1_INTEGER *ai = NULL;

    ai = ASN1_INTEGER_new();
    if(ai == NULL)
    {
        goto err;
    }

    in = BIO_new_file(serialfile, "r");
    if(in == NULL) 
    {
        if(!create) 
        {
            goto err;
        }

        ret = BN_new();
        if(ret == NULL || !rand_serial(ret, ai))
        {
            std::cout << "Out of memory" << std::endl;
        }
    }
	else 
    {
        if(!a2i_ASN1_INTEGER(in, ai, buf, 1024))
        {
            goto err;
        }
        
        ret = ASN1_INTEGER_to_BN(ai, NULL);
        
        if(ret == NULL) 
        {
            goto err;
        }
    }

    if(ret && retai)
    {
        *retai = ai;
        ai = NULL;
    }

 err:

    BIO_free(in);
    ASN1_INTEGER_free(ai);
    return ret;
}

bool CaWrapper::generateX509(X509_REQ *x509Req, X509 *x509Ca, EVP_PKEY *caPkey, BIGNUM *serial, long days, int email_dn, STACK_OF(CONF_VALUE) *policy,const EVP_MD *dgst)
{

}

bool CaWrapper::ca(const std::string &inputConfigFile, const std::string &inputCsrFile)
{
    bool ret = false;
    char *entry = NULL, *cnfData = NULL, *caPrivateKeyFile = NULL, *caCertificateFile = NULL;
    const EVP_MD *evpMd = NULL;
    unsigned long chtype = MBSTRING_ASC;
	long days = 0;
	int email_dn = 1;
    EVP_PKEY *pkey = NULL;
    STACK_OF(CONF_VALUE) *policy = NULL;
    CnfWrapper cnfwrapper;
    KeyWrapper cakeywrapper;
    CertWrapper cacertwrapper;
    CsrWrapper csrwrapper;

    if(inputConfigFile.empty() == true || inputCsrFile.empty() == true)
    {
        return false;
    }

    ret = cnfwrapper.loadConf(inputConfigFile);
    if(ret == false)
    {
        return false;
    }

    entry = cnfwrapper.lookupEntry(BASE_SECTION, ENV_DEFAULT_CA);
    if(entry == NULL)
    {
        return false;
    }

    // 1. get serial number information from configuration file
    cnfData = cnfwrapper.getString(entry, ENV_SERIAL);
    unique_ptr_bn_type_t upBnSerial(load_serial(cnfData, 1, NULL), delRawPtrBN);
    if(upBnSerial == nullptr)
    {
        return false;
    }

    // 2. get string mask from configuration file
    cnfData = cnfwrapper.getString(entry, STRING_MASK);
	if(cnfData == NULL)
	{
		return false;
	}

	if(ASN1_STRING_set_default_mask_asc(cnfData) == 0)
	{
		return false;
	}

    // 3. get character type from configuration file
    cnfData = cnfwrapper.getString(entry, UTF8_IN);
    if(cnfData == NULL)
    {
        return false;
    }

    if(std::strcmp(cnfData, "yes") == 0)
    {
        chtype = MBSTRING_UTF8;
    }

    // 4. get request extension from configuration file
    cnfData = cnfwrapper.getString(entry, ENV_EXTENSIONS);
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

    // 5. get default md from configuration file
    cnfData = cnfwrapper.getString(entry, ENV_DEFAULT_MD);
    if(cnfData == NULL)
    {
        return false;
    }

	evpMd = EVP_get_digestbyname(cnfData);
	if(evpMd == NULL)
	{
		return false;
	}

    // 6. get CA private key filename information from configuration file
    caPrivateKeyFile = cnfwrapper.getString(entry, ENV_PRIVATE_KEY);
    if(caPrivateKeyFile == NULL)
    {
        return false;
    }

    // 7. get CA certificate filename information from configuration file
    caCertificateFile = cnfwrapper.getString(entry, ENV_CERTIFICATE);
    if(caCertificateFile == NULL)
    {
        return false;
    }

    // 8. get email deny information from configuration file
	cnfData = cnfwrapper.getString(entry, ENV_DEFAULT_EMAIL_DN);
	if(cnfData == NULL)
	{
		return false;
	}

	if(std::strcmp(cnfData, "no") == 0)
	{
		email_dn = 0;
	}

    // 9. get day information from configuration file
	days = cnfwrapper.getNumber(entry, ENV_DEFAULT_DAYS);
	if(days < 3600)
	{
		return false;
	}

    // 10. get policy information from configuration file
	cnfData = cnfwrapper.getString(entry, ENV_POLICY);
	if(cnfData == NULL)
	{
		return false;
	}

    policy = cnfwrapper.getSection(cnfwrapper.getConf(), cnfData);
	if(policy == NULL)
	{
		return false;
	}

    // 11. read ca private key
    ret = cakeywrapper.loadPrivateKey(caPrivateKeyFile, FORMAT_PEM);
    if(ret == false)
    {
        return false;
    }

    // 12. read ca certificate
    ret = cacertwrapper.readCert(caCertificateFile, FORMAT_PEM);
    if(ret == false)
    {
        return false;
    }

    // 13. read csr
    ret = csrwrapper.readCsr(inputCsrFile, FORMAT_PEM);
    if(ret == false)
    {
        return false;
    }

    return true;
}

CaWrapper::~CaWrapper()
{
    //X509_free(x509);
    std::cout << "~CaWrapper called.." << std::endl;
}