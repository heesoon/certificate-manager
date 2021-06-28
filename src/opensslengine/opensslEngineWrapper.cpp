#include <iostream>
#include "opensslEngineWrapper.hpp"

#define ENGINE_SO_PATTH_NAME "/home/hskim/github/certificate-manager/build/src/libopensslEngine.so"

OpensslEngineWrapper::OpensslEngineWrapper(const std::string &engineName)
{
    ENGINE *engine = NULL;

	if ((engine = ENGINE_by_id(engineName.c_str())) == NULL && (engine = try_load_engine(engineName.c_str())) == NULL)
    {
		//printf("Error: %s\n", ERR_reason_error_string(ERR_get_error()));
	}

    if(engine != NULL)
    {
        this->engine = engine;
        std::cout << "Success " << std::endl;
    }
}

ENGINE* OpensslEngineWrapper::try_load_engine(const std::string &engineName)
{
    ENGINE *engine = ENGINE_by_id("dynamic");

    if(engine)
    {
        if( !ENGINE_ctrl_cmd_string(engine, "SO_PATH", ENGINE_SO_PATTH_NAME, 0)
            || !ENGINE_ctrl_cmd_string(engine, "ID", engineName.c_str(), 0)
            || !ENGINE_ctrl_cmd_string(engine, "LOAD", NULL, 0)
        )
        {
            ENGINE_free(engine);
            engine = NULL;
        }
    }

    return engine;
}

ENGINE* OpensslEngineWrapper::getEngine()
{
    return engine;
}

bool OpensslEngineWrapper::loadKey(const std::string &keyId)
{
    //ENGINE_LOAD_KEY_PTR pkeyLoadMethod = ENGINE_get_load_privkey_function(engine);
    //pkeyLoadMethod(engine, keyId.c_str(), NULL, NULL);
    if(engine == NULL)
    {
        return false;
    }
    ENGINE_init(engine);
    ENGINE_load_private_key(engine, "test", NULL, NULL);
    ENGINE_finish(engine);
}

OpensslEngineWrapper::~OpensslEngineWrapper()
{
    ENGINE_free(engine);
}
