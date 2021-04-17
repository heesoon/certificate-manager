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

#if defined(LOG_PRINT)
#define LOGE(x) std::cout << "ERROR : " << "[" << __FILE__ << ", " << __FUNCTION__ << ", " << __LINE__ << "] " << x << std::endl;
#define LOGI(x) std::cout << "INFO : " << "[" << __FILE__ << ", " << __FUNCTION__ << ", " << __LINE__ << "] " << x << std::endl;
#define LOGD(x) std::cout << "DEBUG : " << "[" << __FILE__ << ", " << __FUNCTION__ << ", " << __LINE__ << "] " << x << std::endl;
#else
#define LOGE(x)
#define LOGI(x)
#define LOGD(x)
#endif

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

X509_STORE* setup_verify(const char *CAfile)
{
    X509_STORE *store = NULL;
    X509_LOOKUP *lookup;
    //OSSL_LIB_CTX *libctx = app_get0_libctx();
    //const char *propq = app_get0_propq();	

    OSSL_LIB_CTX *libctx = NULL;
    const char *propq = NULL;	


	if(CAfile == NULL)
	{
		LOGE("wrong input parameter")
		goto end;
	}

	store = X509_STORE_new();
	if(store == NULL)
	{
		LOGE("X509_STORE_new")
		goto end;
	}

	lookup = X509_STORE_add_lookup(store, X509_LOOKUP_file());
	if(lookup == NULL)
	{
		LOGE("X509_STORE_new")
		goto end;
	}

	if (!X509_LOOKUP_load_file_ex(lookup, CAfile, X509_FILETYPE_PEM, libctx, propq))
	{
		LOGE("X509_LOOKUP_load_file_ex")
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

bool check(X509_STORE *ctx, const char *input_certificate_file, bool show_chain)
{
	int i = 0;
	bool ret = false;
	BIO *bio = NULL;
	X509 *x509 = NULL;
	X509_STORE_CTX *csc = NULL;
	STACK_OF(X509) *chain = NULL;
	int num_untrusted;

	bio = BIO_new_file(input_certificate_file, modestr('r', FORMAT_PEM));
	if(bio == NULL)
	{
		LOGE("BIO_new_file")
		goto end;		
	}

	x509 = PEM_read_bio_X509_AUX(bio, NULL, NULL, NULL);
	if(x509 == NULL)
	{
		LOGE("PEM_read_bio_X509_AUX")
		goto end;
	}

	csc = X509_STORE_CTX_new();
	if(csc == NULL)
	{
		LOGE("X509_STORE_CTX_new")
		goto end;
	}

	X509_STORE_set_flags(ctx, 0);

	if(!X509_STORE_CTX_init(csc, ctx, x509, NULL))
	{
		 X509_STORE_CTX_free(csc);
		LOGE("X509_STORE_CTX_init")
		goto end;
	}

	i = X509_verify_cert(csc);

	if(i > 0 && X509_STORE_CTX_get_error(csc) == X509_V_OK)
	{
		LOGI("Verification OK")
		ret = true;

		if(show_chain == true)
		{
			int j = 0;

			chain = X509_STORE_CTX_get1_chain(csc);
			num_untrusted = X509_STORE_CTX_get_num_untrusted(csc);
			LOGD("Chain:")

			for(j = 0; j < sk_X509_num(chain); j++)
			{
				X509 *cert = sk_X509_value(chain, j);
				LOGD("depth = " << j)

				if(j < num_untrusted)
				{
					LOGD("(untrusted)")
				}
			}

			sk_X509_pop_free(chain, X509_free);
		}
	}
	else
	{
		LOGE("Verification failed")
		goto end;
	}

	X509_STORE_CTX_free(csc);
end:
	X509_free(x509);
	return (ret == true) ? true : false;
}

bool verify(const char *input_ca_chain_file, const char *input_certificate_file)
{
	bool ret = false;
	X509_STORE *store = NULL;

	if(input_ca_chain_file == NULL || input_certificate_file == NULL)
	{
		LOGE("wrong input parameter")
		goto end;
	}

	store = setup_verify(input_ca_chain_file);
	if(store == NULL)
	{
		LOGE("setup_verify")
		goto end;		
	}

	X509_STORE_set_verify_cb(store, NULL);

	if(check(store, input_certificate_file, true) == false)
	{
		LOGE("check")
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

void test_verify()
{
	bool ret = false;
	std::string input_ca_chain_file = "/home/hskim/certificates/intermediate/certs/ca-chain.cert.pem";
	std::string input_certificate_file = "/home/hskim/certificates/customer/certs/customer.cert.pem";

	ret = verify(input_ca_chain_file.c_str(), input_certificate_file.c_str());
	if(ret == false)
	{
		LOGE("input_certificate_file")
		return;
	}

	LOGI("Success")
}

int main()
{
	test_verify();
	return 0;
}