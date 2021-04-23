#include <iostream>
#include "bioWrapper.hpp"
#include "CsrWrapper.hpp"
#include "KeyWrapper.hpp"
#include "CnfWrapper.hpp"
#include "CaWrapper.hpp"
#include <openssl/x509v3.h>


CaWrapper::CaWrapper()
{
}

CaWrapper::~CaWrapper()
{
    std::cout << "~CaWrapper called.." << std::endl;
}