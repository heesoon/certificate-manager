#include <cstring>
#include <string>
#include "Log.hpp"
#include "OpensslBioWrapper.hpp"
#include "OpensslConfWrapper.hpp"
#include "OpensslRsaKeyWrapper.hpp"
#include "OpensslCsrWrapper.hpp"
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

auto delRawPtrX509Name = [](X509_NAME *x509Name)
{
    X509_NAME_free(x509Name);
    PmLogDebug("[%s, %d] delRawPtrX509Name called ..", __FUNCTION__, __LINE__);
};
using unique_ptr_x509Name_type_t = std::unique_ptr<X509_NAME, decltype(delRawPtrX509Name)>;

auto delRawPtrX509Req = [](X509_REQ *x509Req)
{
    X509_REQ_free(x509Req);
    PmLogDebug("[%s, %d] delRawPtrX509Req called ..", __FUNCTION__, __LINE__);
};
using unique_ptr_x509Req_type_t = std::unique_ptr<X509_REQ, decltype(delRawPtrX509Req)>;

OpensslCsrWrapper::OpensslCsrWrapper()
{
    x509Req = NULL;
}

bool OpensslCsrWrapper::open(const std::string &filename, char mode, int format)
{
    if(filename.empty() == true)
    {
        PmLogError("[%s, %d] Bio open fail", __FUNCTION__, __LINE__);
        return false;
    }

    std::unique_ptr<OpensslBioWrapper> upTempBio(new OpensslBioWrapper());
    if(upTempBio == nullptr)
    {
        PmLogError("[%s, %d] Bio open fail", __FUNCTION__, __LINE__);
        return false;
    }

    if(upTempBio->open(filename, mode, format) == false)
    {
        PmLogError("[%s, %d] Bio open fail", __FUNCTION__, __LINE__);
        return false;
    }

    upBio = std::move(upTempBio);
    return true;
}

bool OpensslCsrWrapper::read()
{
    BIO *bio = NULL;
    X509_REQ *req = NULL;
    char mode = ' ';
    int format = 0;

    if(upBio == nullptr)
    {
        PmLogError("[%s, %d]", __FUNCTION__, __LINE__);
        return false;
    }

    mode = upBio->getOpenMode();
    if(mode != 'r')
    {
        PmLogError("[%s, %d]", __FUNCTION__, __LINE__);
        return false;
    }

    bio = upBio->getBio();
    if(bio == NULL)
    {
        PmLogError("[%s, %d]", __FUNCTION__, __LINE__);
        return false;
    }

    format = upBio->getOpenFormat();
    if(format == FORMAT_ASN1)
    {
        req = d2i_X509_REQ_bio(bio, NULL);
    }
    else if(format == FORMAT_PEM)
    {
        req = PEM_read_bio_X509_REQ(bio, NULL, NULL, NULL);
    }
    else
    {
        PmLogError("[%s, %d] Not Supported", __FUNCTION__, __LINE__);
        return false;
    }

    if(req == NULL)
    {
        PmLogError("[%s, %d]", __FUNCTION__, __LINE__);
        return false;
    }

    this->x509Req = req;
    return true;
}

bool OpensslCsrWrapper::write(X509_REQ *x509Req)
{
    int ret = 0;
    BIO *bio = NULL;
    char mode = ' ';
    int format = 0;

    if(x509Req == NULL)
    {
        PmLogError("[%s, %d]", __FUNCTION__, __LINE__);
        return false;
    }

    if(upBio == nullptr)
    {
        PmLogError("[%s, %d]", __FUNCTION__, __LINE__);
        return false;
    }

    mode = upBio->getOpenMode();
    if(mode != 'w')
    {
        PmLogError("[%s, %d]", __FUNCTION__, __LINE__);
        return false;
    }

    bio = upBio->getBio();
    if(bio == NULL)
    {
        PmLogError("[%s, %d]", __FUNCTION__, __LINE__);
        return false;        
    }

    format = upBio->getOpenFormat();
    if(format == FORMAT_ASN1)
    {
        ret = i2d_X509_REQ_bio(bio, x509Req);
    }
    else if(format == FORMAT_PEM)
    {
        ret = PEM_write_bio_X509_REQ(bio, x509Req);
        //ret = PEM_write_bio_X509_REQ_NEW(csr, x509);
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

bool OpensslCsrWrapper::makeCsr(const std::string &inputCnfFilename, const std::string &inputKeyFilename, const subject_t &subject)
{
    int ret = 0;
    char mode = ' ';
    //int format = 0;
    char *cnfData = NULL;
    char *req_exts = NULL;
    const EVP_MD *evpMd = NULL;
    X509_REQ *x509tReq = NULL;
    X509_NAME *x509_name = NULL;
    EVP_PKEY *evpKey = NULL;
    EVP_PKEY *tpubkey = NULL;
    unsigned long chtype = MBSTRING_ASC;
    OpensslConfWrapper opensslConfWrapper;
    OpensslRsaKeyWrapper opensslRsaKeyWrapper;

    if(inputCnfFilename.empty() == true || inputKeyFilename.empty() == true)
    {
        PmLogError("[%s, %d]", __FUNCTION__, __LINE__);
        return false;        
    }

    mode = upBio->getOpenMode();
    if(mode != 'w')
    {
        PmLogError("[%s, %d]", __FUNCTION__, __LINE__);
        return false;
    }

    //format = upBio->getOpenFormat();

    if(opensslConfWrapper.open(inputCnfFilename) == false)
    {
        PmLogError("[%s, %d]", __FUNCTION__, __LINE__);
        return false;
    }

    // 1. get default md from configuration file
    cnfData = opensslConfWrapper.getString(REQ_BASE_SECTION, DEFAULT_MD);
    if(cnfData == NULL)
    {
        PmLogError("[%s, %d]", __FUNCTION__, __LINE__);
        return false;
    }

	evpMd = EVP_get_digestbyname(cnfData);
	if(evpMd == NULL)
	{
        PmLogError("[%s, %d]", __FUNCTION__, __LINE__);
		return false;
	}

    // 2. get string mask from configuration file
    cnfData = opensslConfWrapper.getString(REQ_BASE_SECTION, STRING_MASK);
    if(cnfData == NULL)
    {
        PmLogError("[%s, %d]", __FUNCTION__, __LINE__);
        return false;
    }

    ret = ASN1_STRING_set_default_mask_asc(cnfData);
    if(ret == 0)
    {
        PmLogError("[%s, %d]", __FUNCTION__, __LINE__);
        return false;
    }

    // 3. get character type from configuration file
    cnfData = opensslConfWrapper.getString(REQ_BASE_SECTION, UTF8_IN);
    if(cnfData == NULL)
    {
        PmLogError("[%s, %d]", __FUNCTION__, __LINE__);
        return false;
    }

    if(std::strcmp(cnfData, "yes") == 0)
    {
        chtype = MBSTRING_UTF8;
    }

    // 4. get request extension from configuration file
    req_exts = opensslConfWrapper.getString(REQ_BASE_SECTION, REQ_EXTENSIONS);
    if(req_exts != NULL)
    {
        /* Check syntax of file */
        X509V3_CTX ctx;
        CONF* conf = opensslConfWrapper.getConf();
        X509V3_set_ctx_test(&ctx);
        X509V3_set_nconf(&ctx, conf);
        if(!X509V3_EXT_add_nconf(conf, &ctx, req_exts, NULL))
        {
            PmLogError("[%s, %d]", __FUNCTION__, __LINE__);
            return false;
        }
    }
    // 5. TO DO. if need to add more value from configuration file

    // 6. set subject from input
    //x509_name = X509_NAME_new();
    unique_ptr_x509Name_type_t upX509Name(X509_NAME_new(), delRawPtrX509Name);
    x509_name = upX509Name.get();
    if(x509_name == NULL)
    {
        PmLogError("[%s, %d]", __FUNCTION__, __LINE__);
        return false;
    }

	ret = X509_NAME_add_entry_by_txt(x509_name, "commonName", chtype, reinterpret_cast<const unsigned char*>(subject.countryName.c_str()), -1, -1, 0);
	if(ret == 0)
	{
        PmLogError("[%s, %d]", __FUNCTION__, __LINE__);
		return false;
	}

	ret = X509_NAME_add_entry_by_txt(x509_name, "countryName", chtype, reinterpret_cast<const unsigned char*>(subject.countryName.c_str()), -1, -1, 0);
	if(ret == 0)
	{
        PmLogError("[%s, %d]", __FUNCTION__, __LINE__);
		return false;
	}

	ret = X509_NAME_add_entry_by_txt(x509_name, "stateOrProvinceName", chtype, reinterpret_cast<const unsigned char*>(subject.stateOrProvinceName.c_str()), -1, -1, 0);
	if(ret == 0)
	{
        PmLogError("[%s, %d]", __FUNCTION__, __LINE__);
		return false;
	}

	ret = X509_NAME_add_entry_by_txt(x509_name, "localityName", chtype, reinterpret_cast<const unsigned char*>(subject.localityName.c_str()), -1, -1, 0);
	if(ret == 0)
	{
        PmLogError("[%s, %d]", __FUNCTION__, __LINE__);
		return false;
	}

	ret = X509_NAME_add_entry_by_txt(x509_name, "organizationName", chtype, reinterpret_cast<const unsigned char*>(subject.organizationName.c_str()), -1, -1, 0);
	if(ret == 0)
	{
        PmLogError("[%s, %d]", __FUNCTION__, __LINE__);
		return false;
	}

	ret = X509_NAME_add_entry_by_txt(x509_name, "emailAddress", chtype, reinterpret_cast<const unsigned char*>(subject.emailAddress.c_str()), -1, -1, 0);
	if(ret == 0)
	{
        PmLogError("[%s, %d]", __FUNCTION__, __LINE__);
		return false;
	}

    // 7. read public key
    //if(opensslRsaKeyWrapper.open(inputKeyFilename, 'r', format) == false)
    if(opensslRsaKeyWrapper.open(inputKeyFilename, 'r', FORMAT_PEM) == false)
    {
        PmLogError("[%s, %d]", __FUNCTION__, __LINE__);
        return false;
    }

    if(opensslRsaKeyWrapper.read(PKEY_TYPE_T::PKEY_PRIVATE_KEY, "") == false)
    {
        PmLogError("[%s, %d]", __FUNCTION__, __LINE__);
        return false;
    }

    // 8. build X509_REQ structure
    x509tReq = X509_REQ_new();
    //unique_ptr_x509Req_type_t upX509Req(X509_REQ_new(), delRawPtrX509Req);
    //x509tReq = upX509Req.get();
  	if(x509tReq == NULL)
	{
        PmLogError("[%s, %d]", __FUNCTION__, __LINE__);
		return false;
	}

	// 8.1. setting req revsion. currently there is only version 1
	ret = X509_REQ_set_version(x509tReq, 0L);
	if(ret == 0)
	{
        PmLogError("[%s, %d]", __FUNCTION__, __LINE__);
		goto error;
	}

	// 8.2. setting subject to req
	ret = X509_REQ_set_subject_name(x509tReq, x509_name);
	if(ret == 0)
	{
        PmLogError("[%s, %d]", __FUNCTION__, __LINE__);
		goto error;
	}

    // 8.3. setting subject to req
    //evpKey = keywrapper.getEvpPrivateKey(ENUM_KEY_TYPE::LOADED_FROM_FILE);
	evpKey = opensslRsaKeyWrapper.getPkey();
	ret = X509_REQ_set_pubkey(x509tReq, evpKey);
	if(ret == 0)
	{
        PmLogError("[%s, %d]", __FUNCTION__, __LINE__);
		goto error;
	}

    // 8.4. get request extension from configuration file
    if(req_exts != NULL)
    {
        /* Check syntax of file */
        X509V3_CTX ctx;
        CONF* conf = opensslConfWrapper.getConf();
        //X509V3_set_ctx_test(&ctx);
        X509V3_set_ctx(&ctx, NULL, NULL, x509tReq, NULL, 0);
        X509V3_set_nconf(&ctx, conf);
        if(!X509V3_EXT_REQ_add_nconf(conf, &ctx, req_exts, x509tReq))
        {
            PmLogError("[%s, %d]", __FUNCTION__, __LINE__);
            goto error;
        }
    }

    // 8.5. signing
	ret = X509_REQ_sign(x509tReq, evpKey, evpMd);
	if(ret == 0)
	{
        PmLogError("[%s, %d]", __FUNCTION__, __LINE__);
		goto error;
	}

    // 8.6. req verify
	tpubkey = evpKey;
	if(tpubkey == NULL)
	{
		tpubkey = X509_REQ_get0_pubkey(x509tReq);
		if(tpubkey == NULL)
		{
            PmLogError("[%s, %d]", __FUNCTION__, __LINE__);
			goto error;
		}
	}

	ret = X509_REQ_verify(x509tReq, tpubkey);
	if(ret <= 0)
	{
        PmLogError("[%s, %d]", __FUNCTION__, __LINE__);
		goto error;
	}

    PmLogDebug("[%s, %d] Success", __FUNCTION__, __LINE__);
    this->x509Req = x509tReq;
    return true;

error:
    X509_REQ_free(x509tReq);
    return false;
}

X509_REQ* OpensslCsrWrapper::getX509Req()
{
    return x509Req;
}

void OpensslCsrWrapper::close()
{
    X509_REQ_free(x509Req);
    x509Req = NULL;
}

OpensslCsrWrapper::~OpensslCsrWrapper()
{
    X509_REQ_free(x509Req);
    PmLogDebug("[%s, %d]", __FUNCTION__, __LINE__);
}