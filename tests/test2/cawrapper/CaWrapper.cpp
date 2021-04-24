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

bool CaWrapper::init()
{
    x509 = X509_new();
    if(x509 == NULL)
    {
        return false;
    }

    return true;
}

bool CaWrapper::randSerial(BIGNUM *b, ASN1_INTEGER *ai)
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

BIGNUM* CaWrapper::loadSerial(const char *serialfile, int create, ASN1_INTEGER **retai)
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
        if(ret == NULL || !randSerial(ret, ai))
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

bool CaWrapper::setCertTimes(const char *startdate, const char *enddate, int days)
{
    if(x509 == NULL)
    {
        return false;
    }

    if(startdate == NULL || strcmp(startdate, "today") == 0) 
    {
        if(X509_gmtime_adj(X509_getm_notBefore(x509), 0) == NULL)
        {
            return false;
        }
    } 
    else
    {
        if(!ASN1_TIME_set_string_X509(X509_getm_notBefore(x509), startdate))
        {
            return false;
        }
    }

    if(enddate == NULL)
    {
        if(X509_time_adj_ex(X509_getm_notAfter(x509), days, 0, NULL) == NULL)
        {
            return false;
        }
    }
    else if(!ASN1_TIME_set_string_X509(X509_getm_notAfter(x509), enddate))
    {
        return false;
    }

    return true;
}

int CaWrapper::pkey_ctrl_string(EVP_PKEY_CTX *ctx, const char *value)
{
    int rv = 0;
    char *stmp, *vtmp = NULL;

    stmp = OPENSSL_strdup(value);
    if (stmp == NULL)
        return -1;
    vtmp = strchr(stmp, ':');
    if (vtmp == NULL)
        goto err;

    *vtmp = 0;
    vtmp++;
    rv = EVP_PKEY_CTX_ctrl_str(ctx, stmp, vtmp);

 err:
    OPENSSL_free(stmp);
    return rv;
}

int CaWrapper::do_pkey_ctx_init(EVP_PKEY_CTX *pkctx, STACK_OF(OPENSSL_STRING) *opts)
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

int CaWrapper::adapt_keyid_ext(X509 *cert, X509V3_CTX *ext_ctx, const char *name, const char *value, int add_default)
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

int CaWrapper::do_sign_init(EVP_MD_CTX *ctx, EVP_PKEY *pkey, const EVP_MD *md, STACK_OF(OPENSSL_STRING) *sigopts)
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

int CaWrapper::do_X509_sign(X509 *cert, EVP_PKEY *pkey, const EVP_MD *md, STACK_OF(OPENSSL_STRING) *sigopts, X509V3_CTX *ext_ctx)
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


bool CaWrapper::generateX509(X509_REQ *x509Req, X509 *x509Ca, EVP_PKEY *caPkey, BIGNUM *serial, long days, int emailDn, STACK_OF(CONF_VALUE) *policy ,const EVP_MD *evpMd)
{
    bool ret = false;
    int i = 0, j = 0, last = 0;
	const X509_NAME *x509ReqSubject = NULL;
    const X509_NAME *x509CaSubject = NULL; 
	X509_NAME *subject = NULL;
	X509_NAME_ENTRY *ne, *tne;
	ASN1_STRING *str, *str2;
    EVP_PKEY *pkeyPublic;
	CONF_VALUE *cv;
	ASN1_OBJECT *obj;
    X509V3_CTX ext_ctx;

    if(x509 == NULL)
    {
        goto end;
    }

    // 1. get subject from X509_REQ (certificate sign request)
	x509ReqSubject = X509_REQ_get_subject_name(x509Req);
	if(x509ReqSubject == NULL)
	{
		goto end;
	}
	
    // 2. get subject from X509
	x509CaSubject = X509_NAME_dup(X509_get_subject_name(x509Ca));
	if(x509CaSubject == NULL)
	{
        goto end;
	}

    // 3. integrate both X509_REQ and X509
	subject = X509_NAME_new();
	if(subject == NULL)
	{
		goto end;
	}

    // 4. integrate both X509_REQ and X509
	for(i = 0; i < sk_CONF_VALUE_num(policy); i++)
	{
		cv = sk_CONF_VALUE_value(policy, i);
		if((j = OBJ_txt2nid(cv->name)) == NID_undef)
		{
			goto end;
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
					goto end;
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
					goto end;
				}

				last2 = -1;

again2:
				j = X509_NAME_get_index_by_OBJ(x509CaSubject, obj, last2);
				if ((j < 0) && (last2 == -1))
				{
					goto end;
				}

				if(j >= 0)
				{
					push = X509_NAME_get_entry(x509CaSubject, j);
					str = X509_NAME_ENTRY_get_data(tne);
					str2 = X509_NAME_ENTRY_get_data(push);
					last2 = j;
					if(ASN1_STRING_cmp(str, str2) != 0)
						goto again2;
				}

				if(j < 0)
				{
					goto end;
				}
			}
			else
			{
				goto end;
			}

			if(push != NULL)
			{
				if(!X509_NAME_add_entry(subject, push, -1, 0))
				{
					goto end;
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
		goto end;
	}

    // 5. set issuer name to x509
	if(!X509_set_issuer_name(x509, X509_get_subject_name(x509Ca)))
	{
		goto end;
	}

    // 6. set subject name to x509
	if(!X509_set_subject_name(x509, subject))
	{
		goto end;
	}

    // 7. set days to x509
    if(setCertTimes(NULL, NULL, days) == false)
    {
        goto end;
    }

    // 8. set public key to x509
	pkeyPublic = X509_REQ_get0_pubkey(x509Req);
	i = X509_set_pubkey(x509, pkeyPublic);
	if(i == 0)
	{
		goto end;
	}

    // 9. set email to x509
	if(!emailDn)
	{
        X509_NAME_ENTRY *tmpne;
        X509_NAME *dn_subject;

        if((dn_subject = X509_NAME_dup(subject)) == NULL) 
		{
            goto end;
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
            goto end;
        }
        X509_NAME_free(dn_subject);		
	}

    // 10. set CA public key to x509
	pkeyPublic = X509_get0_pubkey(x509Ca);

    if(EVP_PKEY_missing_parameters(pkeyPublic) && !EVP_PKEY_missing_parameters(caPkey))
	{
		EVP_PKEY_copy_parameters(pkeyPublic, caPkey);
	}

    // Initialize the context structure
	X509V3_set_ctx(&ext_ctx, x509Ca, x509, x509Req, NULL, X509V3_CTX_REPLACE);

    if(!do_X509_sign(x509, caPkey, evpMd, NULL, &ext_ctx))
	{
		goto end;
	}

    ret = true;

end:
    if(ret == false)
    {
        X509_free(x509);
        X509_NAME_free(subject);
    }

    return ret;
}

bool CaWrapper::ca(const std::string &inputConfigFile, const std::string &inputCsrFile)
{
    bool ret = false;
    long days = 0;
    int emailDn = 1;
    unsigned long chtype = MBSTRING_ASC;
    EVP_PKEY *pkey = NULL;
    X509_REQ *x509Req = NULL;
    X509 *x509Ca = NULL;
    EVP_PKEY *caPkey;
    const EVP_MD *evpMd = NULL;
    STACK_OF(CONF_VALUE) *policy = NULL;
    char *entry = NULL, *cnfData = NULL, *caPrivateKeyFile = NULL, *caCertificateFile = NULL;
    CnfWrapper cnfwrapper;
    KeyWrapper cakeywrapper;
    CertWrapper cacertwrapper;
    CsrWrapper csrwrapper;

    if(x509 == NULL)
    {
        return false;
    }

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
    unique_ptr_bn_type_t upBnSerial(loadSerial(cnfData, 1, NULL), delRawPtrBN);
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
        if(!X509V3_EXT_add_nconf(conf, &ctx, cnfData, x509))
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
		emailDn = 0;
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

    // == prepare for generating signed certificate by CA
    x509Req = csrwrapper.getX509ReadReq();
    if(x509Req == NULL)
    {
        return false;
    }

    x509Ca = cacertwrapper.getX509();
    if(x509Ca == NULL)
    {
        return false;
    }

    caPkey = cakeywrapper.getLoadedEvpPrivateKey();
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

bool CaWrapper::saveSignedCert(const std::string &outputFile, int format)
{
    CertWrapper cert;
    if(cert.writeCert(x509, outputFile, format) == false)
    {
        return false;
    }

    return true;
}

X509_STORE* CaWrapper::setup_verify(const std::string &inputCaFile)
{
    X509_STORE *store = NULL;
    X509_LOOKUP *lookup = NULL;

    if(inputCaFile.empty() == true)
    {
        goto end;
    }

	store = X509_STORE_new();
	if(store == NULL)
	{
		goto end;
	}

	lookup = X509_STORE_add_lookup(store, X509_LOOKUP_file());
	if(lookup == NULL)
	{
		goto end;
	}

	if (!X509_LOOKUP_load_file_ex(lookup, inputCaFile.c_str(), X509_FILETYPE_PEM, NULL, NULL))
	{
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

bool CaWrapper::check(X509_STORE *ctx, const std::string &inputCertFile, bool show_chain)
{
    bool ret = false;
	int i = 0;
    int num_untrusted;
	X509_STORE_CTX *csc = NULL;
	STACK_OF(X509) *chain = NULL;
    X509 *x509 = NULL;
    CertWrapper certWrapper;

    certWrapper.readCert(inputCertFile, FORMAT_PEM);
    x509 = certWrapper.getX509();
    if(x509 == NULL)
    {
        std::cout << "x509 error" << std::endl;
        goto end;
    }

	csc = X509_STORE_CTX_new();
	if(csc == NULL)
	{
		goto end;
	}

	X509_STORE_set_flags(ctx, 0);

	if(!X509_STORE_CTX_init(csc, ctx, x509, NULL))
	{
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

bool CaWrapper::verify(const std::string &inputCaChainFile, const std::string &inputCertFile)
{
	bool ret = false;
	X509_STORE *store = NULL;

	if(inputCaChainFile.empty() == true || inputCertFile.empty() == true)
	{
		goto end;
	}

	store = setup_verify(inputCaChainFile);
	if(store == NULL)
	{
		goto end;		
	}

	X509_STORE_set_verify_cb(store, NULL);

	if(check(store, inputCertFile, true) == false)
	{
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

CaWrapper::~CaWrapper()
{
    X509_free(x509);
    std::cout << "~CaWrapper called.." << std::endl;
}