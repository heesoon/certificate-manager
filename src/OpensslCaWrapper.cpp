#include <cstring>
#include <string>
#include "Log.hpp"
#include "OpensslBioWrapper.hpp"
#include "OpensslConfWrapper.hpp"
#include "OpensslRsaKeyWrapper.hpp"
#include "OpensslCaWrapper.hpp"
#include "OpensslCertWrapper.hpp"
#include "OpensslCsrWrapper.hpp"
#include <openssl/x509v3.h>
#include <openssl/x509v3.h>
#include <openssl/pem.h>

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

auto delRawPtrX509_NAME  = [](X509_NAME *subject)
{
    X509_NAME_free(subject);
    PmLogDebug("[%s, %d] delRawPtrX509_NAME called ..", __FUNCTION__, __LINE__);
};
using unique_ptr_x509_name_t = std::unique_ptr<X509_NAME, decltype(delRawPtrX509_NAME)>;

OpensslCaWrapper::OpensslCaWrapper()
{
    x509 = NULL;
}

bool OpensslCaWrapper::open(const std::string &filename, char mode, int format)
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

bool OpensslCaWrapper::read()
{
    BIO *bio = NULL;
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
        x509 = d2i_X509_bio(bio, NULL);
    }
    else if(format == FORMAT_PKCS12)
    {
        // TO DO.
        PmLogError("[%s, %d]", __FUNCTION__, __LINE__);
        return false;
    }
    else if(format == FORMAT_PEM)
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
    char mode = ' ';
    int format = 0;

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
        ret = i2d_X509_bio(bio, x509);
    }
    else if(format == FORMAT_PKCS12)
    {
        // TO DO.
        PmLogError("[%s, %d] Not Supported", __FUNCTION__, __LINE__);
        return false;
    }
    else if(format == FORMAT_PEM)
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

bool OpensslCaWrapper::randSerial(BIGNUM *b, ASN1_INTEGER *ai)
{
    bool ret = false;
    BIGNUM *btmp;

    btmp = b == NULL ? BN_new() : b;
    if(btmp == NULL)
    {
		PmLogError("[%s, %d]", __FUNCTION__, __LINE__);
        return false;
    }

    if(!BN_rand(btmp, SERIAL_RAND_BITS, BN_RAND_TOP_ANY, BN_RAND_BOTTOM_ANY))
    {
		PmLogError("[%s, %d]", __FUNCTION__, __LINE__);
        goto error;
    }

    if(ai && !BN_to_ASN1_INTEGER(btmp, ai))
    {
		PmLogError("[%s, %d]", __FUNCTION__, __LINE__);
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

BIGNUM* OpensslCaWrapper::loadSerial(const char *serialfile, int create, ASN1_INTEGER **retai)
{
    BIO *in = NULL;
    BIGNUM *ret = NULL;
    char buf[1024];
    ASN1_INTEGER *ai = NULL;

    ai = ASN1_INTEGER_new();
    if(ai == NULL)
    {
		PmLogError("[%s, %d]", __FUNCTION__, __LINE__);
        goto err;
    }

    in = BIO_new_file(serialfile, "r");
    if(in == NULL) 
    {
        if(!create) 
        {
			PmLogError("[%s, %d]", __FUNCTION__, __LINE__);
            goto err;
        }

        ret = BN_new();
        if(ret == NULL || !randSerial(ret, ai))
        {
            //std::cout << "Out of memory" << std::endl;
        }
    }
	else 
    {
        if(!a2i_ASN1_INTEGER(in, ai, buf, 1024))
        {
			PmLogError("[%s, %d]", __FUNCTION__, __LINE__);
            goto err;
        }
        
        ret = ASN1_INTEGER_to_BN(ai, NULL);
        
        if(ret == NULL) 
        {
			PmLogError("[%s, %d]", __FUNCTION__, __LINE__);
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

bool OpensslCaWrapper::setCertTimes(X509 *x509, const char *startdate, const char *enddate, int days)
{
    if(x509 == NULL)
    {
        PmLogError("[%s, %d]", __FUNCTION__, __LINE__);
        return false;
    }

    if(startdate == NULL || strcmp(startdate, "today") == 0) 
    {
        if(X509_gmtime_adj(X509_getm_notBefore(x509), 0) == NULL)
        {
            PmLogError("[%s, %d]", __FUNCTION__, __LINE__);
            return false;
        }
    } 
    else
    {
        if(!ASN1_TIME_set_string_X509(X509_getm_notBefore(x509), startdate))
        {
            PmLogError("[%s, %d]", __FUNCTION__, __LINE__);
            return false;
        }
    }

    if(enddate == NULL)
    {
        if(X509_time_adj_ex(X509_getm_notAfter(x509), days, 0, NULL) == NULL)
        {
            PmLogError("[%s, %d]", __FUNCTION__, __LINE__);
            return false;
        }
    }
    else if(!ASN1_TIME_set_string_X509(X509_getm_notAfter(x509), enddate))
    {
        PmLogError("[%s, %d]", __FUNCTION__, __LINE__);
        return false;
    }

    return true;
}

int OpensslCaWrapper::pkey_ctrl_string(EVP_PKEY_CTX *ctx, const char *value)
{
    int rv = 0;
    char *stmp, *vtmp = NULL;

    stmp = OPENSSL_strdup(value);
    if (stmp == NULL)
        return -1;
    vtmp = strchr(stmp, ':');
    if (vtmp == NULL)
	{
		PmLogError("[%s, %d]", __FUNCTION__, __LINE__);
        goto err;
	}

    *vtmp = 0;
    vtmp++;
    rv = EVP_PKEY_CTX_ctrl_str(ctx, stmp, vtmp);

 err:
    OPENSSL_free(stmp);
    return rv;
}

int OpensslCaWrapper::do_pkey_ctx_init(EVP_PKEY_CTX *pkctx, STACK_OF(OPENSSL_STRING) *opts)
{
    int i;

    if (opts == NULL)
        return 1;

    for(i = 0; i < sk_OPENSSL_STRING_num(opts); i++)
    {
        char *opt = sk_OPENSSL_STRING_value(opts, i);
        if (pkey_ctrl_string(pkctx, opt) <= 0)
        {
            return 0;
        }
    }

    return 1;
}

int OpensslCaWrapper::adapt_keyid_ext(X509 *cert, X509V3_CTX *ext_ctx, const char *name, const char *value, int add_default)
{
    const STACK_OF(X509_EXTENSION) *exts = X509_get0_extensions(cert);
    X509_EXTENSION *new_ext = X509V3_EXT_nconf(NULL, ext_ctx, name, value);
    int idx, rv = 0;

    if (new_ext == NULL)
        return rv;

    idx = X509v3_get_ext_by_OBJ(exts, X509_EXTENSION_get_object(new_ext), -1);
    if (idx >= 0)
    {
        X509_EXTENSION *found_ext = X509v3_get_ext(exts, idx);
        ASN1_OCTET_STRING *data = X509_EXTENSION_get_data(found_ext);
        int disabled = ASN1_STRING_length(data) <= 2; /* config said "none" */

        if (disabled)
        {
            X509_delete_ext(cert, idx);
            X509_EXTENSION_free(found_ext);
        } /* else keep existing key identifier, which might be outdated */
        rv = 1;
    }
    else
    {
        rv = !add_default || X509_add_ext(cert, new_ext, -1);
    }

    X509_EXTENSION_free(new_ext);
    return rv;
}

int OpensslCaWrapper::do_sign_init(EVP_MD_CTX *ctx, EVP_PKEY *pkey, const EVP_MD *md, STACK_OF(OPENSSL_STRING) *sigopts)
{
    EVP_PKEY_CTX *pkctx = NULL;
    int def_nid;

    if (ctx == NULL)
        return 0;
    /*
     * EVP_PKEY_get_default_digest_nid() returns 2 if the digest is mandatory
     * for this algorithm.
     */
    if (EVP_PKEY_get_default_digest_nid(pkey, &def_nid) == 2 && def_nid == NID_undef)
    {
        /* The signing algorithm requires there to be no digest */
        md = NULL;
    }
    return EVP_DigestSignInit(ctx, &pkctx, md, NULL, pkey)
        && do_pkey_ctx_init(pkctx, sigopts);
}

int OpensslCaWrapper::do_X509_sign(X509 *cert, EVP_PKEY *pkey, const EVP_MD *md, STACK_OF(OPENSSL_STRING) *sigopts, X509V3_CTX *ext_ctx)
{
    const STACK_OF(X509_EXTENSION) *exts = X509_get0_extensions(cert);
    EVP_MD_CTX *mctx = EVP_MD_CTX_new();
    int self_sign;
    int rv = 0;

    if (sk_X509_EXTENSION_num(exts /* may be NULL */) > 0)
    {
        /* Prevent X509_V_ERR_EXTENSIONS_REQUIRE_VERSION_3 */
        if (!X509_set_version(cert, 2)) /* Make sure cert is X509 v3 */
            goto end;

        /*
         * Add default SKID before such that default AKID can make use of it
         * in case the certificate is self-signed
         */
        /* Prevent X509_V_ERR_MISSING_SUBJECT_KEY_IDENTIFIER */
        if (!adapt_keyid_ext(cert, ext_ctx, "subjectKeyIdentifier", "hash", 1))
            goto end;
        /* Prevent X509_V_ERR_MISSING_AUTHORITY_KEY_IDENTIFIER */
        //ERR_set_mark();
        self_sign = X509_check_private_key(cert, pkey);
        //ERR_pop_to_mark();
        if (!adapt_keyid_ext(cert, ext_ctx, "authorityKeyIdentifier",
                             "keyid, issuer", !self_sign))
            goto end;

        /* TODO any further measures for ensuring default RFC 5280 compliance */
    }

    if (mctx != NULL && do_sign_init(mctx, pkey, md, sigopts) > 0)
        rv = (X509_sign_ctx(cert, mctx) > 0);
 end:
    EVP_MD_CTX_free(mctx);
    return rv;
}

bool OpensslCaWrapper::generateX509(X509 *x509, X509_REQ *x509Req, X509 *x509Ca, CONF *conf, const char *ext_sect, EVP_PKEY *caPkey, BIGNUM *serial, long days, int emailDn, STACK_OF(CONF_VALUE) *policy ,const EVP_MD *evpMd)
{
    int i = 0, j = 0, last = 0;
    char mode = ' ';
	const X509_NAME *x509ReqSubject = NULL;
    const X509_NAME *x509CaSubject = NULL; 
	X509_NAME *subject = NULL;
	//X509_NAME_ENTRY *ne, *tne;
	X509_NAME_ENTRY *tne = NULL;
	ASN1_STRING *str, *str2;
    EVP_PKEY *pkeyPublic;
	CONF_VALUE *cv;
	ASN1_OBJECT *obj;
    X509V3_CTX ext_ctx;

    mode = upBio->getOpenMode();
    if(mode != 'w')
    {
        PmLogError("[%s, %d]", __FUNCTION__, __LINE__);
        return false;
    }

    if(x509 == NULL || x509Req == NULL || x509Ca == NULL || conf == NULL || caPkey == NULL || serial == NULL || policy == NULL || evpMd == NULL)
    {
        PmLogError("[%s, %d]", __FUNCTION__, __LINE__);
        return false;
    }

   // 1. get subject from X509_REQ (certificate sign request)
	x509ReqSubject = X509_REQ_get_subject_name(x509Req);
	if(x509ReqSubject == NULL)
	{
        PmLogError("[%s, %d]", __FUNCTION__, __LINE__);
        return false;
	}

    // 2. get subject from X509
	x509CaSubject = X509_NAME_dup(X509_get_subject_name(x509Ca));
	if(x509CaSubject == NULL)
	{
        PmLogError("[%s, %d]", __FUNCTION__, __LINE__);
        return false;
	}

    // 3. integrate both X509_REQ and X509
    unique_ptr_x509_name_t upX509Name(X509_NAME_new(), delRawPtrX509_NAME);
	subject = upX509Name.get();
	if(subject == NULL)
	{
        PmLogError("[%s, %d]", __FUNCTION__, __LINE__);
        return false;
	}

    // 4. integrate both X509_REQ and X509
	for(i = 0; i < sk_CONF_VALUE_num(policy); i++)
	{
		cv = sk_CONF_VALUE_value(policy, i);
		if((j = OBJ_txt2nid(cv->name)) == NID_undef)
		{
            PmLogError("[%s, %d]", __FUNCTION__, __LINE__);
            return false;
		}

		obj = OBJ_nid2obj(j);
		last = -1;

		for(;;)
		{
			X509_NAME_ENTRY *push = NULL;
			j = X509_NAME_get_index_by_OBJ(x509ReqSubject, obj, last);
			if(j < 0)
			{
				if(last != -1)
				{
					break;
				}

				tne = NULL;
			}
			else
			{
				tne = X509_NAME_get_entry(x509ReqSubject, j);
			}
			last = j;

			/* depending on the 'policy', decide what to do. */
			if(std::strcmp(cv->value, "optional") == 0)
			{
				if(tne != NULL)
				{
					push = tne;
				}
			}
			else if(std::strcmp(cv->value, "supplied") == 0)
			{
				if(tne == NULL)
				{
                    PmLogError("[%s, %d]", __FUNCTION__, __LINE__);
                    return false;
				}
				else
				{
					push = tne;
				}
			}
			else if (std::strcmp(cv->value, "match") == 0)
			{
				int last2;

				if(tne == NULL)
				{
                    PmLogError("[%s, %d]", __FUNCTION__, __LINE__);
                    return false;
				}

				last2 = -1;

again2:
				j = X509_NAME_get_index_by_OBJ(x509CaSubject, obj, last2);
				if ((j < 0) && (last2 == -1))
				{
                    PmLogError("[%s, %d]", __FUNCTION__, __LINE__);
                    return false;
				}

				if(j >= 0)
				{
					push = X509_NAME_get_entry(x509CaSubject, j);
					str = X509_NAME_ENTRY_get_data(tne);
					str2 = X509_NAME_ENTRY_get_data(push);
					last2 = j;
					if(ASN1_STRING_cmp(str, str2) != 0)
                    {
                        goto again2;
                    }
				}

				if(j < 0)
				{
                    PmLogError("[%s, %d]", __FUNCTION__, __LINE__);
                    return false;
				}
			}
			else
			{
                PmLogError("[%s, %d]", __FUNCTION__, __LINE__);
                return false;
			}

			if(push != NULL)
			{
				if(!X509_NAME_add_entry(subject, push, -1, 0))
				{
                    PmLogError("[%s, %d]", __FUNCTION__, __LINE__);
                    return false;
				}
			}

			if(j < 0)
			{
				break;
			}
		}
	}

    // 5. set serial number to x509
	if(BN_to_ASN1_INTEGER(serial, X509_get_serialNumber(x509)) == NULL)
	{
        PmLogError("[%s, %d]", __FUNCTION__, __LINE__);
        return false;
	}

    // 5. set issuer name to x509
	if(!X509_set_issuer_name(x509, X509_get_subject_name(x509Ca)))
	{
        PmLogError("[%s, %d]", __FUNCTION__, __LINE__);
        return false;
	}

    // 6. set subject name to x509
	if(!X509_set_subject_name(x509, subject))
	{
        PmLogError("[%s, %d]", __FUNCTION__, __LINE__);
        return false;
	}

    // 7. set days to x509
    if(setCertTimes(x509, NULL, NULL, days) == false)
    {
        PmLogError("[%s, %d]", __FUNCTION__, __LINE__);
        return false;
    }

    // 8. set public key to x509
	pkeyPublic = X509_REQ_get0_pubkey(x509Req);
	i = X509_set_pubkey(x509, pkeyPublic);
	if(i == 0)
	{
        PmLogError("[%s, %d]", __FUNCTION__, __LINE__);
        return false;
	}

    // 9. Initialize the context structure
	X509V3_set_ctx(&ext_ctx, x509Ca, x509, x509Req, NULL, X509V3_CTX_REPLACE);

    // 10. get request extension from configuration file
    if(ext_sect != NULL)
    {
        X509V3_set_nconf(&ext_ctx, conf);
        if(!X509V3_EXT_add_nconf(conf, &ext_ctx, ext_sect, x509))
        {
            return false;
        }
    }

    // 11. set email to x509
	if(!emailDn)
	{
        X509_NAME_ENTRY *tmpne;
        X509_NAME *dn_subject;

        if((dn_subject = X509_NAME_dup(subject)) == NULL) 
		{
            PmLogError("[%s, %d]", __FUNCTION__, __LINE__);
            return false;
        }

		i = -1;

        while((i = X509_NAME_get_index_by_NID(dn_subject, NID_pkcs9_emailAddress, i)) >= 0)
		{
            tmpne = X509_NAME_delete_entry(dn_subject, i--);
            X509_NAME_ENTRY_free(tmpne);
        }

        if(!X509_set_subject_name(x509, dn_subject))
		{
            X509_NAME_free(dn_subject);
            PmLogError("[%s, %d]", __FUNCTION__, __LINE__);
            return false;
        }
        X509_NAME_free(dn_subject);		
	}

#if 0
    // 12. set CA public key to x509
	pkeyPublic = X509_get0_pubkey(x509Ca);

    if(EVP_PKEY_missing_parameters(pkeyPublic) && !EVP_PKEY_missing_parameters(caPkey))
	{
		EVP_PKEY_copy_parameters(pkeyPublic, caPkey);
	}
#else
    // 12. set CA public key to x509
	pkeyPublic = X509_get0_pubkey(x509);

    if(EVP_PKEY_missing_parameters(pkeyPublic) && !EVP_PKEY_missing_parameters(caPkey))
	{
		EVP_PKEY_copy_parameters(pkeyPublic, caPkey);
	}
#endif
    if(!do_X509_sign(x509, caPkey, evpMd, NULL, &ext_ctx))
	{
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
    //EVP_PKEY *pkey = NULL;
    X509_REQ *x509Req = NULL;
    X509 *x509Ca = NULL;
    EVP_PKEY *caPkey;
    char *extensions = NULL;
    //CONF *conf = NULL;
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
		PmLogError("[%s, %d]", __FUNCTION__, __LINE__);
        return false;
    }

    if(inputConfigFile.empty() == true || inputCsrFile.empty() == true)
    {
		PmLogError("[%s, %d]", __FUNCTION__, __LINE__);
        return false;
    }

    ret = opensslConfWrapper.open(inputConfigFile);
    if(ret == false)
    {
		PmLogError("[%s, %d]", __FUNCTION__, __LINE__);
        return false;
    }

    entry = opensslConfWrapper.lookupEntry(BASE_SECTION, ENV_DEFAULT_CA);
    if(entry == NULL)
    {
		PmLogError("[%s, %d]", __FUNCTION__, __LINE__);
        return false;
    }

    // 1. get serial number information from configuration file
    cnfData = opensslConfWrapper.getString(entry, ENV_SERIAL);
    unique_ptr_bn_t upBnSerial(loadSerial(cnfData, 1, NULL), delRawPtrBN);
    if(upBnSerial == nullptr)
    {
		PmLogError("[%s, %d]", __FUNCTION__, __LINE__);
        return false;
    }

    // 2. get string mask from configuration file
    cnfData = opensslConfWrapper.getString(entry, STRING_MASK);
	if(cnfData == NULL)
	{
		PmLogError("[%s, %d]", __FUNCTION__, __LINE__);
		return false;
	}

	if(ASN1_STRING_set_default_mask_asc(cnfData) == 0)
	{
		PmLogError("[%s, %d]", __FUNCTION__, __LINE__);
		return false;
	}

    // 3. get character type from configuration file
    cnfData = opensslConfWrapper.getString(entry, UTF8_IN);
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
    extensions = opensslConfWrapper.getString(entry, ENV_EXTENSIONS);
    if(extensions != NULL)
    {
        /* Check syntax of file */
        X509V3_CTX ctx;
        CONF* conf = opensslConfWrapper.getConf();
        X509V3_set_ctx_test(&ctx);
        X509V3_set_nconf(&ctx, conf);
        if(!X509V3_EXT_add_nconf(conf, &ctx, extensions, NULL))
        {
			PmLogError("[%s, %d]", __FUNCTION__, __LINE__);
            return false;
        }
    }

    // 5. get default md from configuration file
    cnfData = opensslConfWrapper.getString(entry, ENV_DEFAULT_MD);
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

    // 6. get CA private key filename information from configuration file
    caPrivateKeyFile = opensslConfWrapper.getString(entry, ENV_PRIVATE_KEY);
    if(caPrivateKeyFile == NULL)
    {
		PmLogError("[%s, %d]", __FUNCTION__, __LINE__);
        return false;
    }

    // 7. get CA certificate filename information from configuration file
    caCertificateFile = opensslConfWrapper.getString(entry, ENV_CERTIFICATE);
    if(caCertificateFile == NULL)
    {
		PmLogError("[%s, %d]", __FUNCTION__, __LINE__);
        return false;
    }

    // 8. get email deny information from configuration file
	cnfData = opensslConfWrapper.getString(entry, ENV_DEFAULT_EMAIL_DN);
	if(cnfData == NULL)
	{
		PmLogError("[%s, %d]", __FUNCTION__, __LINE__);
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
		PmLogError("[%s, %d]", __FUNCTION__, __LINE__);
		return false;
	}

    // 10. get policy information from configuration file
	cnfData = opensslConfWrapper.getString(entry, ENV_POLICY);
	if(cnfData == NULL)
	{
		PmLogError("[%s, %d]", __FUNCTION__, __LINE__);
		return false;
	}

    policy = opensslConfWrapper.getSection(opensslConfWrapper.getConf(), cnfData);
	if(policy == NULL)
	{
		PmLogError("[%s, %d]", __FUNCTION__, __LINE__);
		return false;
	}

    // 11. read ca private key
    ret = opensslRsaKeyWrapper.open(caPrivateKeyFile, 'r', FORMAT_PEM, 0);
    if(ret == false)
    {
		PmLogError("[%s, %d]", __FUNCTION__, __LINE__);
        return false;
    }

    ret = opensslRsaKeyWrapper.read(PKEY_TYPE_T::PKEY_PRIVATE_KEY, "");
    if(ret == false)
    {
		PmLogError("[%s, %d]", __FUNCTION__, __LINE__);
        return false;
    }

    // 12. read ca certificate
    ret = opensslCertWrapper.open(caCertificateFile, 'r', FORMAT_PEM);
    if(ret == false)
    {
		PmLogError("[%s, %d]", __FUNCTION__, __LINE__);
        return false;
    }

    ret = opensslCertWrapper.read();
    if(ret == false)
    {
		PmLogError("[%s, %d]", __FUNCTION__, __LINE__);
        return false;
    }    

    // check CA private key and CA certificate
    if(!X509_check_private_key(opensslCertWrapper.getX509(), opensslRsaKeyWrapper.getPkey()))
    {
		PmLogError("[%s, %d]", __FUNCTION__, __LINE__);
        return false;
    }

    // 13. read csr
    ret = opensslCsrWrapper.open(inputCsrFile, 'r', FORMAT_PEM);
    if(ret == false)
    {
		PmLogError("[%s, %d]", __FUNCTION__, __LINE__);
        return false;
    }

    ret = opensslCsrWrapper.read();
    if(ret == false)
    {
		PmLogError("[%s, %d]", __FUNCTION__, __LINE__);
        return false;
    }

    // == prepare for generating signed certificate by CA
    x509Req = opensslCsrWrapper.getX509Req();
    if(x509Req == NULL)
    {
		PmLogError("[%s, %d]", __FUNCTION__, __LINE__);
        return false;
    }

    x509Ca = opensslCertWrapper.getX509();
    if(x509Ca == NULL)
    {
		PmLogError("[%s, %d]", __FUNCTION__, __LINE__);
        return false;
    }

    caPkey = opensslRsaKeyWrapper.getPkey();
    if(caPkey == NULL)
    {
		PmLogError("[%s, %d]", __FUNCTION__, __LINE__);
        return false;
    }

    // 14. generated signed certificate by CA based on certificate signed request
    if(generateX509(upX509.get(), x509Req, x509Ca, opensslConfWrapper.getConf(), extensions, caPkey, upBnSerial.get(), days, emailDn, policy, evpMd) == false)
    {
		PmLogError("[%s, %d]", __FUNCTION__, __LINE__);
        return false;
    }

    this->x509 = upX509.release();
    return true;
}

X509_STORE* OpensslCaWrapper::setup_verify(const std::string &inputCaFile)
{
    X509_STORE *store = NULL;
    X509_LOOKUP *lookup = NULL;

    if(inputCaFile.empty() == true)
    {
		PmLogError("[%s, %d]", __FUNCTION__, __LINE__);
        goto end;
    }

	store = X509_STORE_new();
	if(store == NULL)
	{
		PmLogError("[%s, %d]", __FUNCTION__, __LINE__);
		goto end;
	}

	lookup = X509_STORE_add_lookup(store, X509_LOOKUP_file());
	if(lookup == NULL)
	{
		PmLogError("[%s, %d]", __FUNCTION__, __LINE__);
		goto end;
	}

	if (!X509_LOOKUP_load_file_ex(lookup, inputCaFile.c_str(), X509_FILETYPE_PEM, NULL, NULL))
	{
		PmLogError("[%s, %d]", __FUNCTION__, __LINE__);
		goto end;		
	}

	return store;

end:
	if(store != NULL)
	{
		X509_STORE_free(store);
	}

	return NULL;
}

bool OpensslCaWrapper::check(X509_STORE *ctx, const std::string &inputCertFile, bool show_chain)
{
    bool ret = false;
	int i = 0;
    int num_untrusted;
	X509_STORE_CTX *csc = NULL;
	STACK_OF(X509) *chain = NULL;
    X509 *x509 = NULL;
    OpensslCertWrapper opensslCertWrapper;

    opensslCertWrapper.open(inputCertFile, 'r', FORMAT_PEM);
    opensslCertWrapper.read();
    x509 = opensslCertWrapper.getX509();
    if(x509 == NULL)
    {
        PmLogDebug("[%s, %d]", __FUNCTION__, __LINE__);
        goto end;
    }

	csc = X509_STORE_CTX_new();
	if(csc == NULL)
	{
		PmLogError("[%s, %d]", __FUNCTION__, __LINE__);
		goto end;
	}

	X509_STORE_set_flags(ctx, 0);

	if(!X509_STORE_CTX_init(csc, ctx, x509, NULL))
	{
		PmLogError("[%s, %d]", __FUNCTION__, __LINE__);
		 X509_STORE_CTX_free(csc);
		goto end;
	}

	i = X509_verify_cert(csc);

	if(i > 0 && X509_STORE_CTX_get_error(csc) == X509_V_OK)
	{
		ret = true;

		if(show_chain == true)
		{
			int j = 0;

			chain = X509_STORE_CTX_get1_chain(csc);
			num_untrusted = X509_STORE_CTX_get_num_untrusted(csc);

			for(j = 0; j < sk_X509_num(chain); j++)
			{
				X509 *cert = sk_X509_value(chain, j);
				X509_NAME_print_ex_fp(stdout, X509_get_subject_name(cert), 0, XN_FLAG_COMPAT);

				if(j < num_untrusted)
				{
					//LOGD("(untrusted)")
				}
			}

			sk_X509_pop_free(chain, X509_free);
		}
	}
	else
	{
		goto end;
	}

	X509_STORE_CTX_free(csc);
end:
	//X509_free(x509);
	return (ret == true) ? true : false;
}

bool OpensslCaWrapper::verifyByCa(const std::string &inputCaChainFile, const std::string &inputCertFile)
{
	bool ret = false;
	X509_STORE *store = NULL;

	if(inputCaChainFile.empty() == true || inputCertFile.empty() == true)
	{
		PmLogError("[%s, %d]", __FUNCTION__, __LINE__);
		goto end;
	}

	store = setup_verify(inputCaChainFile);
	if(store == NULL)
	{
		PmLogError("[%s, %d]", __FUNCTION__, __LINE__);
		goto end;		
	}

	X509_STORE_set_verify_cb(store, NULL);

	if(check(store, inputCertFile, true) == false)
	{
		PmLogError("[%s, %d]", __FUNCTION__, __LINE__);
		goto end;
	}

	ret = true;
end:

	if(store != NULL)
	{
		X509_STORE_free(store);
	}

	return (ret == true) ? true : false;    
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