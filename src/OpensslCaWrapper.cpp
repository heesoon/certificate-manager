#include <cstring>
#include <string>
#include "Log.hpp"
#include "OpensslBioWrapper.hpp"
#include "OpensslConfWrapper.hpp"
#include "OpensslRsaKeyWrapper.hpp"
#include "OpensslCaWrapper.hpp"
#include <openssl/x509v3.h>

#define BASE_SECTION            "ca"

#define ENV_DEFAULT_CA          "default_ca"

#define STRING_MASK             "string_mask"
#define UTF8_IN                 "utf8"

#define ENV_NEW_CERTS_DIR       "new_certs_dir"
#define ENV_CERTIFICATE         "certificate"
#define ENV_SERIAL              "serial"
#define ENV_RAND_SERIAL         "rand_serial"
#define ENV_CRLNUMBER           "crlnumber"
#define ENV_PRIVATE_KEY         "private_key"
#define ENV_DEFAULT_DAYS        "default_days"
#define ENV_DEFAULT_STARTDATE   "default_startdate"
#define ENV_DEFAULT_ENDDATE     "default_enddate"
#define ENV_DEFAULT_CRL_DAYS    "default_crl_days"
#define ENV_DEFAULT_CRL_HOURS   "default_crl_hours"
#define ENV_DEFAULT_MD          "default_md"
#define ENV_DEFAULT_EMAIL_DN    "email_in_dn"
#define ENV_PRESERVE            "preserve"
#define ENV_POLICY              "policy"
#define ENV_EXTENSIONS          "x509_extensions"
#define ENV_CRLEXT              "crl_extensions"
#define ENV_MSIE_HACK           "msie_hack"
#define ENV_NAMEOPT             "name_opt"
#define ENV_CERTOPT             "cert_opt"
#define ENV_EXTCOPY             "copy_extensions"
#define ENV_UNIQUE_SUBJECT      "unique_subject"
#define ENV_DATABASE            "database"

# define SERIAL_RAND_BITS        159

auto delRawPtrX509 = [](X509 *x509)
{
    X509_free(x509);
    PmLogDebug("[%s, %d] delRawPtrX509 called ..", __FUNCTION__, __LINE__);
};
using unique_ptr_x509_t = std::unique_ptr<X509, decltype(delRawPtrX509)>;

auto delRawPtrBN = [](BIGNUM *bn)
{
    BN_free(bn);
    PmLogDebug("[%s, %d] delRawPtrBN called ..", __FUNCTION__, __LINE__);
};
using unique_ptr_bn_t = std::unique_ptr<BIGNUM, decltype(delRawPtrBN)>;

OpensslCaWrapper::OpensslCaWrapper()
{
    x509 = NULL;
    mode = ' ';
    format = 0;
}

bool OpensslCaWrapper::open(const std::string &filename, char mode, int format)
{
    if(filename.empty() == true)
    {
        PmLogError("[%s, %d] Bio open fail", __FUNCTION__, __LINE__);
        return false;
    }

    std::unique_ptr<OpensslBioWrapper> upInternalOpensslBioWrapper(new OpensslBioWrapper());
    if(upInternalOpensslBioWrapper == nullptr)
    {
        PmLogError("[%s, %d] Bio open fail", __FUNCTION__, __LINE__);
        return false;
    }

    if(upInternalOpensslBioWrapper->open(filename, mode, format) == false)
    {
        PmLogError("[%s, %d] Bio open fail", __FUNCTION__, __LINE__);
        return false;
    }

    this->format = format;
    this->mode = mode;
    upOpensslBioWrapper = std::move(upInternalOpensslBioWrapper);

    return true;
}

bool OpensslCaWrapper::read()
{
    BIO *bio = NULL;

    if(this->mode != 'r')
    {
        return false;
    }

    if(upOpensslBioWrapper == nullptr)
    {
        PmLogError("[%s, %d]", __FUNCTION__, __LINE__);
        return false;
    }

    bio = upOpensslBioWrapper->getBio();
    if(bio == NULL)
    {
        PmLogError("[%s, %d]", __FUNCTION__, __LINE__);
        return false;
    }

    if(this->format == FORMAT_ASN1)
    {
        x509 = d2i_X509_bio(bio, NULL);
    }
    else if(this->format == FORMAT_PKCS12)
    {
        // TO DO.
        PmLogError("[%s, %d]", __FUNCTION__, __LINE__);
        return false;
    }
    else if(this->format == FORMAT_PEM)
    {
        x509 = PEM_read_bio_X509_AUX(bio, NULL, NULL, NULL);
    }
    else
    {
        PmLogError("[%s, %d]", __FUNCTION__, __LINE__);
        return false;
    }

    if(x509 == NULL)
    {
        PmLogError("[%s, %d]", __FUNCTION__, __LINE__);
        return false;
    }

    return true;
}

bool OpensslCaWrapper::write(X509 *x509)
{
    int ret = 0;
    BIO *bio = NULL;

    if(this->mode != 'w')
    {
        return false;
    }

    if(x509 == NULL)
    {
        PmLogError("[%s, %d]", __FUNCTION__, __LINE__);
        return false;
    }

    if(upOpensslBioWrapper == nullptr)
    {
        PmLogError("[%s, %d]", __FUNCTION__, __LINE__);
        return false;
    }

    bio = upOpensslBioWrapper->getBio();
    if(bio == NULL)
    {
        PmLogError("[%s, %d]", __FUNCTION__, __LINE__);
        return false;        
    }

    if(this->format == FORMAT_ASN1)
    {
        ret = i2d_X509_bio(bio, x509);
    }
    else if(this->format == FORMAT_PKCS12)
    {
        // TO DO.
        PmLogError("[%s, %d] Not Supported", __FUNCTION__, __LINE__);
        return false;
    }
    else if(this->format == FORMAT_PEM)
    {
        ret = PEM_write_bio_X509_AUX(bio, x509);
        //ret = PEM_write_bio_X509(cert, x509);
    }
    else
    {
        PmLogError("[%s, %d] Not Supported", __FUNCTION__, __LINE__);
        return false;
    }

    if(ret == 0)
    {
        PmLogError("[%s, %d]", __FUNCTION__, __LINE__);
        return false;
    }

    return true;
}

bool OpensslCaWrapper::generateCertSignedByCa(const std::string &inputConfigFile, const std::string &inputCsrFile)
{
    bool ret = false;
    long days = 0;
    int emailDn = 1;
    unsigned long chtype = MBSTRING_ASC;
    EVP_PKEY *pkey = NULL;
    X509_REQ *x509Req = NULL;
    X509 *x509t = NULL;
    X509 *x509Ca = NULL;
    EVP_PKEY *caPkey;
    const EVP_MD *evpMd = NULL;
    STACK_OF(CONF_VALUE) *policy = NULL;
    char *entry = NULL, *cnfData = NULL, *caPrivateKeyFile = NULL, *caCertificateFile = NULL;
    OpensslConfWrapper opensslConfWrapper;
    OpensslRsaKeyWrapper opensslRsaKeyWrapper;
    OpensslCertWrapper opensslCertWrapper;
    OpensslCsrWrapper opensslCsrWrapper;

    unique_ptr_x509_t upX509(X509_new(), delRawPtrX509);
    if(upX509 == nullptr)
    {
        return false;
    }

    if(inputConfigFile.empty() == true || inputCsrFile.empty() == true)
    {
        return false;
    }

    ret = opensslConfWrapper.open(inputConfigFile);
    if(ret == false)
    {
        return false;
    }

    entry = opensslConfWrapper.lookupEntry(BASE_SECTION, ENV_DEFAULT_CA);
    if(entry == NULL)
    {
        return false;
    }

    // 1. get serial number information from configuration file
    cnfData = opensslConfWrapper.getString(entry, ENV_SERIAL);
    unique_ptr_bn_t upBnSerial(loadSerial(cnfData, 1, NULL), delRawPtrBN);
    if(upBnSerial == nullptr)
    {
        return false;
    }

    // 2. get string mask from configuration file
    cnfData = opensslConfWrapper.getString(entry, STRING_MASK);
	if(cnfData == NULL)
	{
		return false;
	}

	if(ASN1_STRING_set_default_mask_asc(cnfData) == 0)
	{
		return false;
	}

    // 3. get character type from configuration file
    cnfData = opensslConfWrapper.getString(entry, UTF8_IN);
    if(cnfData == NULL)
    {
        return false;
    }

    if(std::strcmp(cnfData, "yes") == 0)
    {
        chtype = MBSTRING_UTF8;
    }

    // 4. get request extension from configuration file
    cnfData = opensslConfWrapper.getString(entry, ENV_EXTENSIONS);
    if(cnfData != NULL)
    {
        /* Check syntax of file */
        X509V3_CTX ctx;
        CONF* conf = opensslConfWrapper.getConf();
        X509V3_set_ctx_test(&ctx);
        X509V3_set_nconf(&ctx, conf);
        if(!X509V3_EXT_add_nconf(conf, &ctx, cnfData, x509))
        {
            return false;
        }
    }

    // 5. get default md from configuration file
    cnfData = opensslConfWrapper.getString(entry, ENV_DEFAULT_MD);
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
    caPrivateKeyFile = opensslConfWrapper.getString(entry, ENV_PRIVATE_KEY);
    if(caPrivateKeyFile == NULL)
    {
        return false;
    }

    // 7. get CA certificate filename information from configuration file
    caCertificateFile = opensslConfWrapper.getString(entry, ENV_CERTIFICATE);
    if(caCertificateFile == NULL)
    {
        return false;
    }

    // 8. get email deny information from configuration file
	cnfData = opensslConfWrapper.getString(entry, ENV_DEFAULT_EMAIL_DN);
	if(cnfData == NULL)
	{
		return false;
	}

	if(std::strcmp(cnfData, "no") == 0)
	{
		emailDn = 0;
	}

    // 9. get day information from configuration file
	days = opensslConfWrapper.getNumber(entry, ENV_DEFAULT_DAYS);
	if(days < 3600)
	{
		return false;
	}

    // 10. get policy information from configuration file
	cnfData = opensslConfWrapper.getString(entry, ENV_POLICY);
	if(cnfData == NULL)
	{
		return false;
	}

    policy = opensslConfWrapper.getSection(opensslConfWrapper.getConf(), cnfData);
	if(policy == NULL)
	{
		return false;
	}

    // 11. read ca private key
    ret = opensslRsaKeyWrapper.open(caPrivateKeyFile, 'r', FORMAT_PEM, 0);
    if(ret == false)
    {
        return false;
    }

    ret = opensslRsaKeyWrapper.read(PKEY_TYPE_T::PKEY_PRIVATE_KEY);
    if(ret == false)
    {
        return false;
    }

    // 12. read ca certificate
    ret = opensslCertWrapper.open(caCertificateFile, 'r', FORMAT_PEM);
    if(ret == false)
    {
        return false;
    }

    ret = opensslCertWrapper.read();
    if(ret == false)
    {
        return false;
    }    

    // 13. read csr
    ret = opensslCsrWrapper.open(inputCsrFile, 'r', FORMAT_PEM);
    if(ret == false)
    {
        return false;
    }

    ret = opensslCsrWrapper.read();
    if(ret == false)
    {
        return false;
    }

    // == prepare for generating signed certificate by CA
    x509Req = opensslCsrWrapper.getX509Req();
    if(x509Req == NULL)
    {
        return false;
    }

    x509Ca = opensslCertWrapper.getX509();
    if(x509Ca == NULL)
    {
        return false;
    }

    caPkey = opensslRsaKeyWrapper.getPkey();
    if(caPkey == NULL)
    {
        return false;
    }

    // 14. generated signed certificate by CA based on certificate signed request
    if(generateX509(x509Req, x509Ca, caPkey, upBnSerial.get(), days, emailDn, policy, evpMd) == false)
    {
        return false;
    }

    return true;
}

X509* OpensslCaWrapper::getX509()
{
    return x509;
}

OpensslCaWrapper::~OpensslCaWrapper()
{
    X509_free(x509);
    PmLogDebug("[%s, %d]", __FUNCTION__, __LINE__);
}