#include <openssl/engine.h>
#include <openssl/rsa.h>
# include <openssl/pem.h>
# include <openssl/x509v3.h>

#define SUCCESS 1
#define FAILE   0

# define CMD_LIST_CERTS             ENGINE_CMD_BASE
# define CMD_LOOKUP_CERT            (ENGINE_CMD_BASE + 1)

static const ENGINE_CMD_DEFN cmd_defns[] = {
    {CMD_LIST_CERTS,
     "list_certs",
     "List all certificates in store",
     ENGINE_CMD_FLAG_NO_INPUT},

    {0, NULL, NULL, 0}
};

static int engine_idx = -1;
static int rsa_idx = -1;
static int cert_idx = -1;
static const char *engine_id = "hsm";
static const char *engine_name = "HSM ENGINE";
static RSA_METHOD *rsa_method = NULL;

int rsa_priv_enc(int flen, const unsigned char *from, unsigned char *to, RSA *rsa, int padding)
{
    return -1;
}

int rsa_priv_dec(int flen, const unsigned char *from, unsigned char *to, RSA *rsa, int padding)
{
    return -1;
}

static int rsa_free(RSA *rsa)
{
    return -1;
}

int rsa_sign(int dtype, const unsigned char *m, unsigned int m_len, unsigned char *sigret, unsigned int *siglen, const RSA *rsa)
{
    return -1;
}

static int engine_init(ENGINE *e)
{
    const RSA_METHOD *ossl_rsa_meth;

    if(engine_idx < 0)
    {
        engine_idx = ENGINE_get_ex_new_index(0, NULL, NULL, NULL, 0);
        if(engine_idx < 0)
        {
            return FAILE;
        }

        cert_idx = X509_get_ex_new_index(0, NULL, NULL, NULL, 0);

        /* Setup RSA_METHOD */
        rsa_idx =  RSA_get_ex_new_index(0, NULL, NULL, NULL, 0);
        ossl_rsa_meth = RSA_PKCS1_OpenSSL();
        if(   !RSA_meth_set_pub_enc(rsa_method, RSA_meth_get_pub_enc(ossl_rsa_meth))
            || !RSA_meth_set_pub_dec(rsa_method, RSA_meth_get_pub_dec(ossl_rsa_meth))
            || !RSA_meth_set_priv_enc(rsa_method, rsa_priv_enc)
            || !RSA_meth_set_priv_dec(rsa_method, rsa_priv_dec)
            || !RSA_meth_set_mod_exp(rsa_method, RSA_meth_get_mod_exp(ossl_rsa_meth))
            || !RSA_meth_set_bn_mod_exp(rsa_method, RSA_meth_get_bn_mod_exp(ossl_rsa_meth))
            || !RSA_meth_set_finish(rsa_method, rsa_free)
            || !RSA_meth_set_sign(rsa_method, rsa_sign))
        {
            return FAILE;
        }
    }

    return SUCCESS;
}

static int engine_finish(ENGINE *e)
{
    return SUCCESS;
}

static int engine_destroy(ENGINE *e)
{
    RSA_meth_free(rsa_method);
    rsa_method = NULL;

    return SUCCESS;
}

static EVP_PKEY *engine_load_privkey(ENGINE *eng, const char *key_id, UI_METHOD *ui_method, void *callback_data)
{
    EVP_PKEY *pkey = NULL;

    return pkey;
}

static int engine_load_ssl_client_cert(ENGINE *e, SSL *ssl,
                                     STACK_OF(X509_NAME) *ca_dn, X509 **pcert,
                                     EVP_PKEY **pkey, STACK_OF(X509) **pother,
                                     UI_METHOD *ui_method,
                                     void *callback_data)
{
    return SUCCESS;
}

static int engine_ctrl(ENGINE *e, int cmd, long i, void *p, void (*f) (void))
{
    switch (cmd)
    {
        case CMD_LIST_CERTS:
        break;
        default:
        break;
    }

    return SUCCESS;
}

static int engine_bind(ENGINE *e, const char *id)
{
    if( !ENGINE_set_id(e, engine_id) 
        || !ENGINE_set_name(e, engine_name)
        || !ENGINE_set_init_function(e, engine_init)
        || !ENGINE_set_finish_function(e, engine_finish)
        || !ENGINE_set_destroy_function(e, engine_destroy)
        || !ENGINE_set_RSA(e, rsa_method)
        || !ENGINE_set_load_privkey_function(e, engine_load_privkey)
        || !ENGINE_set_load_ssl_client_cert_function(e, engine_load_ssl_client_cert)
        || !ENGINE_set_cmd_defns(e, cmd_defns)
        || !ENGINE_set_ctrl_function(e, engine_ctrl)
    )
    {
        return FAILE;
    }

    return SUCCESS;
}

IMPLEMENT_DYNAMIC_BIND_FN(engine_bind)
IMPLEMENT_DYNAMIC_CHECK_FN()