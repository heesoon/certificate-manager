#ifndef OPENSSL_ENGINE_WRAPPER_HPP_
#define OPENSSL_ENGINE_WRAPPER_HPP_

#include <openssl/engine.h>
#include <string>
#include <memory>

class OpensslEngineWrapper
{
public:
    OpensslEngineWrapper(const std::string &engineName);
    ENGINE* getEngine();
    bool loadKey(const std::string &keyId);
    virtual ~OpensslEngineWrapper();
private:
    //std::unique_ptr<ENGINE, int(*)(ENGINE*)> upEngine;
    ENGINE *engine;
    ENGINE* try_load_engine(const std::string &engineName);
};
#endif