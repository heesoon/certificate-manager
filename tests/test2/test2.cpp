#include <iostream>
#include <string>
#include <cstring>
#include <memory>
#include <openssl/rsa.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/pem.h>
#include <openssl/conf.h>
 
# define B_FORMAT_TEXT   0x8000
# define FORMAT_UNDEF    0
# define FORMAT_TEXT    (1 | B_FORMAT_TEXT)     /* Generic text */
# define FORMAT_BINARY   2                      /* Generic binary */
# define FORMAT_BASE64  (3 | B_FORMAT_TEXT)     /* Base64 */
# define FORMAT_ASN1     4                      /* ASN.1/DER */
# define FORMAT_PEM     (5 | B_FORMAT_TEXT)
# define FORMAT_PKCS12   6
# define FORMAT_SMIME   (7 | B_FORMAT_TEXT)
# define FORMAT_ENGINE   8                      /* Not really a file format */
# define FORMAT_PEMRSA  (9 | B_FORMAT_TEXT)     /* PEM RSAPublicKey format */
# define FORMAT_ASN1RSA  10                     /* DER RSAPublicKey format */
# define FORMAT_MSBLOB   11                     /* MS Key blob format */
# define FORMAT_PVK      12                     /* MS PVK file format */
# define FORMAT_HTTP     13                     /* Download using HTTP */
# define FORMAT_NSS      14                     /* NSS keylog format */

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

#if defined(LOG_PRINT)
#define LOGE(x) std::cout << "ERROR : " << "[" << __FILE__ << ", " << __FUNCTION__ << ", " << __LINE__ << "] " << x << std::endl;
#define LOGI(x) std::cout << "INFO : " << "[" << __FILE__ << ", " << __FUNCTION__ << ", " << __LINE__ << "] " << x << std::endl;
#define LOGD(x) std::cout << "DEBUG : " << "[" << __FILE__ << ", " << __FUNCTION__ << ", " << __LINE__ << "] " << x << std::endl;
#else
#define LOGE(x)
#define LOGI(x)
#define LOGD(x)
#endif

auto delPtrBN = [](BIGNUM *bn)
{
	if(bn != NULL)
		BN_free(bn);
	LOGD("called ..")
};

auto delPtrBIO = [](BIO *bio)
{
	if(bio != NULL)
		BIO_free(bio);
	// BIO_free_all(bio);
	LOGD("called ..")
};

auto delPtrCONF = [](CONF *conf)
{
	if(conf != NULL)
		NCONF_free(conf);
	LOGD("called ..")
};

auto delPtrX509_REQ = [](X509_REQ *x509_req)
{
	if(x509_req != NULL)
		X509_REQ_free(x509_req);
	LOGD("called ..")
};

auto delPtrX509_NAME = [](X509_NAME *x509_name)
{
	if(x509_name != NULL)
		X509_NAME_free(x509_name);
	LOGD("called ..")
};

auto delPtrEVP_PKEY = [](EVP_PKEY *evp)
{
	if(evp != NULL)
		EVP_PKEY_free(evp);
	LOGD("called ..")
};

auto delPtrX509 = [](X509 *x509)
{
	if(x509 != NULL)
		X509_free(x509);
	LOGD("called ..")
};

using unique_ptr_bn_type_t 				= std::unique_ptr<BIGNUM, decltype(delPtrBN)>;
using unique_ptr_bio_type_t				= std::unique_ptr<BIO, decltype(delPtrBIO)>;
using unique_ptr_conf_type_t			= std::unique_ptr<CONF, decltype(delPtrCONF)>;
using unique_ptr_x509_req_type_t		= std::unique_ptr<X509_REQ, decltype(delPtrX509_REQ)>;
using unique_ptr_x509_name_type_t		= std::unique_ptr<X509_NAME, decltype(delPtrX509_NAME)>;
using unique_ptr_evp_pkey_type_t 		= std::unique_ptr<EVP_PKEY, decltype(delPtrEVP_PKEY)>;
using unique_ptr_x509_type_t			= std::unique_ptr<X509, decltype(delPtrX509)>;

static int istext(int format)
{
    return (format & B_FORMAT_TEXT) == B_FORMAT_TEXT;
}

static const char *modestr(char mode, int format)
{
    OPENSSL_assert(mode == 'a' || mode == 'r' || mode == 'w');

    switch (mode) {
    case 'a':
        return istext(format) ? "a" : "ab";
    case 'r':
        return istext(format) ? "r" : "rb";
    case 'w':
        return istext(format) ? "w" : "wb";
    }
    /* The assert above should make sure we never reach this point */
    return NULL;
}

int rand_serial(BIGNUM *b, ASN1_INTEGER *ai)
{
    BIGNUM *btmp;
    int ret = 0;

    btmp = b == NULL ? BN_new() : b;
    if (btmp == NULL)
        return 0;

    if (!BN_rand(btmp, SERIAL_RAND_BITS, BN_RAND_TOP_ANY, BN_RAND_BOTTOM_ANY))
        goto error;
    if (ai && !BN_to_ASN1_INTEGER(btmp, ai))
        goto error;

    ret = 1;

 error:

    if (btmp != b)
        BN_free(btmp);

    return ret;
}

BIGNUM *load_serial(const char *serialfile, int create, ASN1_INTEGER **retai)
{
    BIO *in = NULL;
    BIGNUM *ret = NULL;
    char buf[1024];
    ASN1_INTEGER *ai = NULL;

    ai = ASN1_INTEGER_new();
    if (ai == NULL)
        goto err;

    in = BIO_new_file(serialfile, "r");
    if (in == NULL) {
        if (!create) {
            perror(serialfile);
            goto err;
        }
        //ERR_clear_error();
        ret = BN_new();
        if (ret == NULL || !rand_serial(ret, ai))
            //BIO_printf(bio_err, "Out of memory\n");
			std::cout << "Out of memory" << std::endl;
    } 
	else {
        if (!a2i_ASN1_INTEGER(in, ai, buf, 1024)) {
            //BIO_printf(bio_err, "Unable to load number from %s\n",
            //           serialfile);
            goto err;
        }
        ret = ASN1_INTEGER_to_BN(ai, NULL);
        if (ret == NULL) {
            //BIO_printf(bio_err, "Error converting number from bin to BIGNUM\n");
            goto err;
        }
    }

    if (ret && retai) {
        *retai = ai;
        ai = NULL;
    }
 err:
    //ERR_print_errors(bio_err);
    BIO_free(in);
    ASN1_INTEGER_free(ai);
    return ret;
}

static char *lookup_conf(const CONF *conf, const char *section, const char *tag)
{
    char *entry = NCONF_get_string(conf, section, tag);
    //if (entry == NULL)
        //BIO_printf(bio_err, "variable lookup failed for %s::%s\n", section, tag);
    return entry;
}

int set_cert_timesset_cert_times(X509 *x, const char *startdate, const char *enddate, int days)
{
    if (startdate == NULL || strcmp(startdate, "today") == 0) {
        if (X509_gmtime_adj(X509_getm_notBefore(x), 0) == NULL)
            return 0;
    } else {
        if (!ASN1_TIME_set_string_X509(X509_getm_notBefore(x), startdate))
            return 0;
    }
    if (enddate == NULL) {
        if (X509_time_adj_ex(X509_getm_notAfter(x), days, 0, NULL)
            == NULL)
            return 0;
    } else if (!ASN1_TIME_set_string_X509(X509_getm_notAfter(x), enddate)) {
        return 0;
    }
    return 1;
}

static int adapt_keyid_ext(X509 *cert, X509V3_CTX *ext_ctx,
                           const char *name, const char *value, int add_default)
{
    const STACK_OF(X509_EXTENSION) *exts = X509_get0_extensions(cert);
    X509_EXTENSION *new_ext = X509V3_EXT_nconf(NULL, ext_ctx, name, value);
    int idx, rv = 0;

    if (new_ext == NULL)
        return rv;

    idx = X509v3_get_ext_by_OBJ(exts, X509_EXTENSION_get_object(new_ext), -1);
    if (idx >= 0) {
        X509_EXTENSION *found_ext = X509v3_get_ext(exts, idx);
        ASN1_OCTET_STRING *data = X509_EXTENSION_get_data(found_ext);
        int disabled = ASN1_STRING_length(data) <= 2; /* config said "none" */

        if (disabled) {
            X509_delete_ext(cert, idx);
            X509_EXTENSION_free(found_ext);
        } /* else keep existing key identifier, which might be outdated */
        rv = 1;
    } else  {
        rv = !add_default || X509_add_ext(cert, new_ext, -1);
    }
    X509_EXTENSION_free(new_ext);
    return rv;
}

int pkey_ctrl_string(EVP_PKEY_CTX *ctx, const char *value)
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

static int do_pkey_ctx_init(EVP_PKEY_CTX *pkctx, STACK_OF(OPENSSL_STRING) *opts)
{
    int i;

    if (opts == NULL)
        return 1;

    for (i = 0; i < sk_OPENSSL_STRING_num(opts); i++) {
        char *opt = sk_OPENSSL_STRING_value(opts, i);
        if (pkey_ctrl_string(pkctx, opt) <= 0) {
            //BIO_printf(bio_err, "parameter error \"%s\"\n", opt);
            //ERR_print_errors(bio_err);
            return 0;
        }
    }

    return 1;
}

static int do_sign_init(EVP_MD_CTX *ctx, EVP_PKEY *pkey,
                        const EVP_MD *md, STACK_OF(OPENSSL_STRING) *sigopts)
{
    EVP_PKEY_CTX *pkctx = NULL;
    int def_nid;

    if (ctx == NULL)
        return 0;
    /*
     * EVP_PKEY_get_default_digest_nid() returns 2 if the digest is mandatory
     * for this algorithm.
     */
    if (EVP_PKEY_get_default_digest_nid(pkey, &def_nid) == 2
            && def_nid == NID_undef) {
        /* The signing algorithm requires there to be no digest */
        md = NULL;
    }
    return EVP_DigestSignInit(ctx, &pkctx, md, NULL, pkey)
        && do_pkey_ctx_init(pkctx, sigopts);
}

int do_X509_sign(X509 *cert, EVP_PKEY *pkey, const EVP_MD *md,
                 STACK_OF(OPENSSL_STRING) *sigopts, X509V3_CTX *ext_ctx)
{
    const STACK_OF(X509_EXTENSION) *exts = X509_get0_extensions(cert);
    EVP_MD_CTX *mctx = EVP_MD_CTX_new();
    int self_sign;
    int rv = 0;

    if (sk_X509_EXTENSION_num(exts /* may be NULL */) > 0) {
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

//unique_ptr_x509_type_t generate_x509(X509 *x509_ca, X509_REQ *req, CONF *conf, const char *extensions, EVP_PKEY *pkey, const EVP_MD *dgst, STACK_OF(CONF_VALUE) *policy, int email_dn, BIGNUM *serial, long days)
X509* generate_x509(X509 *x509_ca, X509_REQ *req, CONF *conf, const char *extensions, EVP_PKEY *pkey, const EVP_MD *dgst, STACK_OF(CONF_VALUE) *policy, int email_dn, BIGNUM *serial, long days)
{
	int i, j, last;
	X509 *x509 = NULL;
	const X509_NAME *name = NULL;
	X509_NAME *CAname = NULL, *subject = NULL;
	EVP_PKEY *pktmp;
	X509_NAME_ENTRY *ne, *tne;
	ASN1_STRING *str, *str2;
	CONF_VALUE *cv;
	ASN1_OBJECT *obj;
	X509V3_CTX ext_ctx;

#if 0
	unique_ptr_x509_type_t up_x509(X509_new(), delPtrX509);
	if(up_x509.get() == NULL)
	{
		LOGE("x509 == NULL")
		goto end;
	}
#else
	x509 = X509_new();
	if(x509 == NULL)
	{
		LOGE("x509 == NULL")
		goto end;
	}	
#endif

	// 1. getting subjects from csr
	name = X509_REQ_get_subject_name(req);
	if(name == NULL)
	{
		LOGE("X509_REQ_get_subject_name == NULL")
		goto end;
	}
	
	CAname = X509_NAME_dup(X509_get_subject_name(x509_ca));
	if(CAname == NULL)
	{
		LOGE("X509_get_subject_name == NULL")
		goto end;
	}

#if 0
	unique_ptr_x509_name_type_t up_x509_name_subject(X509_NAME_new(), delPtrX509_NAME);
	if(up_x509_name_subject.get() == NULL)
	{
		LOGE("x509 == NULL")
		goto end;
	}
#else
	subject = X509_NAME_new();
	if(subject == NULL)
	{
		LOGE("subject == NULL")
		goto end;
	}
#endif

	for(i = 0; i < sk_CONF_VALUE_num(policy); i++)
	{
		cv = sk_CONF_VALUE_value(policy, i);
		if((j = OBJ_txt2nid(cv->name)) == NID_undef)
		{
			LOGE("x509 == NULL")
			goto end;
		}

		obj = OBJ_nid2obj(j);
		last = -1;

		for(;;)
		{
			X509_NAME_ENTRY *push = NULL;
			j = X509_NAME_get_index_by_OBJ(name, obj, last);
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
				tne = X509_NAME_get_entry(name, j);
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
					LOGE("x509 == NULL")
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
					LOGE("x509 == NULL")
					goto end;
				}

				last2 = -1;

again2:
				j = X509_NAME_get_index_by_OBJ(CAname, obj, last2);
				if ((j < 0) && (last2 == -1))
				{
					LOGE("x509 == NULL")
					goto end;
				}

				if(j >= 0)
				{
					push = X509_NAME_get_entry(CAname, j);
					str = X509_NAME_ENTRY_get_data(tne);
					str2 = X509_NAME_ENTRY_get_data(push);
					last2 = j;
					if(ASN1_STRING_cmp(str, str2) != 0)
						goto again2;
				}

				if(j < 0)
				{
					LOGE("x509 == NULL")
					goto end;
				}
			}
			else
			{
				LOGE("x509 == NULL")
				goto end;
			}

			if(push != NULL)
			{
#if 0				
				if(!X509_NAME_add_entry(up_x509_name_subject.get(), push, -1, 0))
				{
					LOGE("x509 == NULL")
					goto end;
				}
#else
				if(!X509_NAME_add_entry(subject, push, -1, 0))
				{
					LOGE("X509_NAME_add_entry")
					goto end;
				}
#endif
			}

			if(j < 0)
			{
				break;
			}
		}
	}

#if 0
	if(BN_to_ASN1_INTEGER(serial, X509_get_serialNumber(up_x509.get())) == NULL)
	{
		LOGE("BN_to_ASN1_INTEGER")
		goto end;
	}

	if(!X509_set_issuer_name(up_x509.get(), X509_get_subject_name(x509_ca)))
	{
		LOGE("X509_set_issuer_name")
		goto end;
	}

	if(set_cert_timesset_cert_times(up_x509.get(), NULL, NULL, days) != 1)
	{
		LOGE("set_cert_timesset_cert_times")
		goto end;
	}

	if(!X509_set_subject_name(up_x509.get(), up_x509_name_subject.get()))
	{
		LOGE("X509_set_subject_name")
		goto end;		
	}

	pktmp = X509_REQ_get0_pubkey(req);
	i = X509_set_pubkey(up_x509.get(), pktmp);
	if(i == 0)
	{
		LOGE("X509_set_pubkey")
		goto end;		
	}

	/* Initialize the context structure */
	X509V3_set_ctx(&ext_ctx, x509_ca, up_x509.get(), req, NULL, X509V3_CTX_REPLACE);
#else
	if(BN_to_ASN1_INTEGER(serial, X509_get_serialNumber(x509)) == NULL)
	{
		LOGE("BN_to_ASN1_INTEGER")
		goto end;
	}

	if(!X509_set_issuer_name(x509, X509_get_subject_name(x509_ca)))
	{
		LOGE("X509_set_issuer_name")
		goto end;
	}

	if(set_cert_timesset_cert_times(x509, NULL, NULL, days) != 1)
	{
		LOGE("set_cert_timesset_cert_times")
		goto end;
	}

	if(!X509_set_subject_name(x509, subject))
	{
		LOGE("X509_set_subject_name")
		goto end;		
	}

	pktmp = X509_REQ_get0_pubkey(req);
	i = X509_set_pubkey(x509, pktmp);
	if(i == 0)
	{
		LOGE("X509_set_pubkey")
		goto end;		
	}

	/* Initialize the context structure */
	X509V3_set_ctx(&ext_ctx, x509_ca, x509, req, NULL, X509V3_CTX_REPLACE);

	if(extensions)
	{
		X509V3_set_nconf(&ext_ctx, conf);
		if(!X509V3_EXT_add_nconf(conf, &ext_ctx, extensions, x509))
		{
			LOGE("X509V3_EXT_add_nconf")
			goto end;
		}
	}

	if(!email_dn)
	{
        X509_NAME_ENTRY *tmpne;
        X509_NAME *dn_subject;

        if((dn_subject = X509_NAME_dup(subject)) == NULL) 
		{
            LOGE("X509_NAME_dup")
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

	pktmp = X509_get0_pubkey(x509);

    if(EVP_PKEY_missing_parameters(pktmp) && !EVP_PKEY_missing_parameters(pkey))
	{
		EVP_PKEY_copy_parameters(pktmp, pkey);
	}

    if (!do_X509_sign(x509, pkey, dgst, NULL, &ext_ctx))
	{
		LOGE("X509_sign")
		goto end;
	}

#endif

	//return std::move(up_x509);
	return x509;

end:
	//return unique_ptr_x509_type_t(NULL, delPtrX509);
	return NULL;
}

bool ca(const char *input_config_filename, const char *input_csr_filename, const char *output_certificate_filename)
{
	int ret = 0;
	long errorline = -1;
	char *pChar = NULL, *section = NULL;;
	char *ca_privatekey_file = NULL;
	char *ca_certificate_file = NULL;
	char *tmp_email_dn = NULL;
	char *md_name = NULL;
	char *policy = NULL;
	const char *serialfile = NULL;
	char *extensions = NULL;
	const EVP_MD *evp_md;
	unsigned long chtype = MBSTRING_ASC;
	long days = 0;
	int email_dn = 1;
	EVP_PKEY *pktmp = NULL;
	STACK_OF(CONF_VALUE) *attribs = NULL;

	if(input_config_filename == NULL || input_csr_filename == NULL || output_certificate_filename == NULL)
	{
		LOGE("wrong input parameter")
		return false;
	}

	// 1. load configuration file. some information is gotten from configuration file
	unique_ptr_bio_type_t up_bio_input_config(BIO_new_file(input_config_filename, modestr('r', FORMAT_TEXT)), delPtrBIO);
	if(up_bio_input_config.get() == NULL)
	{
		LOGE("BIO_new_file");
		return false;
	}

	unique_ptr_conf_type_t up_config(NCONF_new(NULL), delPtrCONF);
	if(up_config.get() == NULL)
	{
		LOGE("BIO_new_file");
		return false;
	}

	ret = NCONF_load_bio(up_config.get(), up_bio_input_config.get(), &errorline);
	if(ret == 0)
	{
		LOGE("NCONF_load_bio");
		return false;
	}

	ret = CONF_modules_load(up_config.get(), NULL, 0);
	if(ret <= 0)
	{
		LOGE("CONF_modules_load");
		return false;
	}

	// load signing algorithm from configuration file
	section = lookup_conf(up_config.get(), BASE_SECTION, ENV_DEFAULT_CA);
	if(section == NULL)
	{
		LOGE("lookup_conf");
		return false;
	}

	//pChar = NCONF_get_string(up_config.get(), BASE_SECTION, STRING_MASK);
	pChar = NCONF_get_string(up_config.get(), section, STRING_MASK);
	if(pChar == NULL)
	{
		LOGE("NCONF_get_string");
		return false;
	}

	ret = ASN1_STRING_set_default_mask_asc(pChar);
	if(ret == 0)
	{
		LOGE("ASN1_STRING_set_default_mask_asc");
		return false;
	}

	if(chtype != MBSTRING_UTF8)
	{
		//pChar = NCONF_get_string(up_config.get(), ENV_DEFAULT_CA, UTF8_IN);
		pChar = NCONF_get_string(up_config.get(), section, UTF8_IN);
		if(pChar == NULL)
		{
			LOGE("NCONF_get_string");
			return false;
		}
		else if(std::strcmp(pChar, "yes") == 0)
		{
			chtype = MBSTRING_UTF8;
		}
	}

    // Getting CA Privatek key filename from configuration //
	//ca_privatekey_file = NCONF_get_string(up_config.get(), ENV_DEFAULT_CA, ENV_PRIVATE_KEY);
	ca_privatekey_file = NCONF_get_string(up_config.get(), section, ENV_PRIVATE_KEY);
	if(ca_privatekey_file == NULL)
	{
		LOGE("ca_privatekey_file");
		return false;
	}

	// read ca private key
	unique_ptr_bio_type_t up_bio_input_ca_private_key(BIO_new_file(ca_privatekey_file, modestr('r', FORMAT_PEM)), delPtrBIO);
	if(up_bio_input_ca_private_key.get() == NULL)
	{
		LOGE("BIO_new_file");
		return false;
	}

	unique_ptr_evp_pkey_type_t up_evp_pkey(PEM_read_bio_PrivateKey(up_bio_input_ca_private_key.get(), NULL, NULL, NULL), delPtrEVP_PKEY);
	if(up_evp_pkey.get() == NULL)
	{
		LOGE("PEM_read_bio_PrivateKey");
		return false;
	}

	// Getting CA certificate filename from configuration //
	//ca_certificate_file = NCONF_get_string(up_config.get(), ENV_DEFAULT_CA, ENV_CERTIFICATE);
	ca_certificate_file = NCONF_get_string(up_config.get(), section, ENV_CERTIFICATE);
	if(ca_certificate_file == NULL)
	{
		LOGE("ca_certificate_file");
		return false;
	}

	// read ca private key
	unique_ptr_bio_type_t up_bio_input_ca_certificate(BIO_new_file(ca_certificate_file, modestr('r', FORMAT_PEM)), delPtrBIO);
	if(up_bio_input_ca_certificate.get() == NULL)
	{
		LOGE("BIO_new_file");
		return false;
	}

	unique_ptr_x509_type_t up_x509_ca(PEM_read_bio_X509_AUX(up_bio_input_ca_certificate.get(), NULL, NULL, NULL), delPtrX509);
	if(up_x509_ca.get() == NULL)
	{
		LOGE("PEM_read_bio_X509_AUX");
		return false;
	}

	// compare private key between loaded private key and loaded private key from certificate
	ret = X509_check_private_key(up_x509_ca.get(), up_evp_pkey.get());
	if(ret == 0)
	{
		LOGE("X509_check_private_key");
		return false;
	}	

	// just skip ENV_PRESERVE, ENV_MSIE_HACK, ENV_NAMEOPT, ENV_CERTOPT
	// TO DO

	//serialfile = NCONF_get_string(up_config.get(), ENV_DEFAULT_CA, ENV_SERIAL);
	serialfile = NCONF_get_string(up_config.get(), section, ENV_SERIAL);
	if(serialfile == NULL)
	{
		LOGE("NCONF_get_string");
		return false;
	}

	unique_ptr_bn_type_t up_bn_serial(load_serial(serialfile, 0, NULL), delPtrBN);
	if(up_bn_serial.get() == NULL)
	{
		LOGE("load_serial");
		return false;
	}	

	// load signing algorithm from configuration file
	//md_name = NCONF_get_string(up_config.get(), ENV_DEFAULT_CA, ENV_DEFAULT_MD);
	md_name = NCONF_get_string(up_config.get(), section, ENV_DEFAULT_MD);
	if(md_name == NULL)
	{
		LOGE("NCONF_get_string");
		return false;
	}

	// 4. getting signing information from configuration file
	evp_md = EVP_get_digestbyname(md_name);
	if(evp_md == NULL)
	{
		LOGE("EVP_get_digestbyname");
		return false;		
	}

	// load signing algorithm from configuration file
	//policy = NCONF_get_string(up_config.get(), ENV_DEFAULT_CA, ENV_POLICY);
	policy = NCONF_get_string(up_config.get(), section, ENV_POLICY);
	if(policy == NULL)
	{
		LOGE("NCONF_get_string");
		return false;
	}

	// load signing algorithm from configuration file
	//tmp_email_dn = NCONF_get_string(up_config.get(), ENV_DEFAULT_CA, ENV_DEFAULT_EMAIL_DN);
	tmp_email_dn = NCONF_get_string(up_config.get(), section, ENV_DEFAULT_EMAIL_DN);
	if(tmp_email_dn == NULL)
	{
		LOGE("NCONF_get_string");
		return false;
	}

	if(std::strcmp(tmp_email_dn, "no") == 0)
	{
		email_dn = 0;
	}

	//extensions = NCONF_get_string(up_config.get(), ENV_DEFAULT_CA, ENV_EXTENSIONS);
	extensions = NCONF_get_string(up_config.get(), section, ENV_EXTENSIONS);
	if(extensions == NULL)
	{
		LOGE("NCONF_get_string");
		return false;
	}

	X509V3_CTX ctx;
	X509V3_set_ctx_test(&ctx);
	X509V3_set_nconf(&ctx, up_config.get());

	ret = X509V3_EXT_add_nconf(up_config.get(), &ctx, extensions, NULL);
	if(ret == 0)
	{
		LOGE("X509V3_EXT_add_nconf");
		return false;		
	}

	//ret = NCONF_get_number(up_config.get(), ENV_DEFAULT_CA, ENV_DEFAULT_DAYS, &days);
	ret = NCONF_get_number(up_config.get(), section, ENV_DEFAULT_DAYS, &days);
	if(ret == 0)
	{
		LOGE("NCONF_get_number");
		return false;		
	}

	attribs = NCONF_get_section(up_config.get(), policy);
	if(attribs == NULL)
	{
		LOGE("NCONF_get_section");
		return false;
	}

	// read csr
	unique_ptr_bio_type_t up_bio_input_csr(BIO_new_file(input_csr_filename, modestr('r', FORMAT_PEM)), delPtrBIO);
	if(up_bio_input_csr.get() == NULL)
	{
		LOGE("BIO_new_file");
		return false;
	}

	unique_ptr_x509_req_type_t up_x509_req(PEM_read_bio_X509_REQ(up_bio_input_csr.get(), NULL, NULL, NULL), delPtrX509_REQ);
	if(up_evp_pkey.get() == NULL)
	{
		LOGE("PEM_read_bio_X509_REQ");
		return false;
	}

	pktmp = X509_REQ_get0_pubkey(up_x509_req.get());
	if(pktmp == NULL)
	{
		LOGE("X509_REQ_get0_pubkey");
		return false;
	}

	ret = X509_REQ_verify(up_x509_req.get(), pktmp);
	if(ret <= 0)
	{
		LOGE("X509_REQ_verify");
		return false;
	}

	unique_ptr_x509_type_t up_x509(generate_x509(up_x509_ca.get(), up_x509_req.get(), up_config.get(), extensions, up_evp_pkey.get(), evp_md, attribs, email_dn, up_bn_serial.get(), days), delPtrX509);
	//unique_ptr_x509_type_t up_x509 = generate_x509(up_x509_ca.get(), up_x509_req.get(), up_config.get(), extensions, up_evp_pkey.get(), evp_md, attribs, email_dn, up_bn_serial.get(), days);
	if(up_x509.get() == NULL)
	{
		LOGE("generate_x509");
		return false;
	}	

	// write certificate
	unique_ptr_bio_type_t up_bio_output_x509(BIO_new_file(output_certificate_filename, modestr('w', FORMAT_PEM)), delPtrBIO);
	if(up_bio_output_x509.get() == NULL)
	{
		LOGE("BIO_new_file");
		return false;
	}

	ret = PEM_write_bio_X509(up_bio_output_x509.get(), up_x509.get());
	if(ret == 0)
	{
		LOGE("PEM_write_bio_X509")
		return false;
	}

	LOGI("Success")
	return true;
}

void test_ca()
{
	bool ret = false;
	std::string input_config_filename = "/home/hskim/share/certificate-manager/tests/test3/scripts/customer_openssl.cnf";
	std::string input_csr_filename = "/home/hskim/certificates/customer/csr/customer.csr.pem";
	std::string output_certificate_filename = "customer_certificate.pem";

	ret = ca(static_cast<const char*>(input_config_filename.c_str()), static_cast<const char*>(input_csr_filename.c_str()), static_cast<const char*>(output_certificate_filename.c_str()));
	if(ret == false)
	{
		LOGE("ca")
		return;
	}

	LOGI("Success")	
}

int main()
{
	test_ca();
	return 0;
}