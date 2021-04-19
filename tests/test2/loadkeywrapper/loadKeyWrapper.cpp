#include <iostream>
#include <memory>
#include <cassert>
#include "loadKeyWrapper.hpp"

LoadKeyWrapper::LoadKeyWrapper()
{
    pkey = NULL;
}

LoadKeyWrapper::~LoadKeyWrapper()
{
    if(pkey != NULL)
    {
        EVP_PKEY_free(pkey);
    }
}