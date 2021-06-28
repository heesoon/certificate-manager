#include <openssl/engine.h>

static const char *engine_id = "hsm";
static const char *engine_name = "HSM ENGINE";

static int engine_init(ENGINE *e)
{
    return 1;
}

static int engine_finish(ENGINE *e)
{
    return 1;
}

static int engine_destroy(ENGINE *e)
{
    return 1;
}

static EVP_PKEY *engine_load_privkey(ENGINE *eng, const char *key_id, UI_METHOD *ui_method, void *callback_data)
{
#if 0    
    BIO *in;
    EVP_PKEY *key;
    fprintf(stderr, "(TEST_ENG_OPENSSL_PKEY)Loading Private key %s\n", key_id);
    in = BIO_new_file(key_id, "r");
    if (!in)
        return NULL;
    key = PEM_read_bio_PrivateKey(in, NULL, 0, NULL);
    BIO_free(in);
    return key;
#endif
    fprintf(stderr, "(TEST_ENG_OPENSSL_PKEY)Loading Private key %s\n", key_id);
    return NULL;
}

static int engine_ctrl(ENGINE *e, int cmd, long i, void *p, void (*f) (void))
{
    return 1;
}

static int engine_bind(ENGINE *e, const char *id)
{   
    if( !ENGINE_set_id(e, engine_id) 
        || !ENGINE_set_name(e, engine_name)
        || !ENGINE_set_init_function(e, engine_init)
        || !ENGINE_set_finish_function(e, engine_finish)
        || !ENGINE_set_destroy_function(e, engine_destroy)
        || !ENGINE_set_load_privkey_function(e, engine_load_privkey)
        //|| !ENGINE_set_load_ssl_client_cert_function(e, engine_load_ssl_client_cert)
        || !ENGINE_set_ctrl_function(e, engine_ctrl)
    )
    {
        return 0;
    }

    return 1;
}

//readelf -s src/libopensslEngine.so | grep bind_engine
extern "C" {
IMPLEMENT_DYNAMIC_BIND_FN(engine_bind)
IMPLEMENT_DYNAMIC_CHECK_FN()
}