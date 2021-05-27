#include "CertificateManager.hpp"
#include "OpensslRsaKeyWrapper.hpp"
#include "Log.hpp"

CertificateManager::CertificateManager()
{
}

bool CertificateManager::generateKey(std::string outputKeyFilename, unsigned int keySize)
{
#if 0	
	bool success = true;
	int nBits = 0;
	EVP_PKEY *pkey = NULL;
	std::string result = "";
	std::string outputKeyFilename = "";
	pbnjson::JValue json;
	pbnjson::JValue request;
	OpensslRsaKeyWrapper opensslRsaKeyWrapper;
	LS::Message lsResponseMsg(&message);

	auto *appid = LSMessageGetApplicationID(&message);
	auto servicename = LSMessageGetSenderServiceName(&message);
	auto *method = LSMessageGetMethod(&message);
	auto *category = LSMessageGetCategory(&message);

    LOG_INFO(MSGID_GENERATOR_KEY, 4,
        PMLOGKS("appid", appid),
        PMLOGKS("servicename", servicename),
        PMLOGKS("method", method),
        PMLOGKS("category", category), " ");

	request = pbnjson::Object();
    request = JUtil::parse(LSMessageGetPayload(&message), "", nullptr);

	outputKeyFilename = request['KeyFilename'].asString();
	if(outputKeyFilename.empty())
	{
		success = false;
		goto end;
	}

	nBits = request['keySize'].asNumber<int>();
	if(nBits <= 1024 || nBits >= 16384)
	{
		success = false;
		goto end;
	}

	if(opensslRsaKeyWrapper.open(outputKeyFilename, 'w', FORMAT_PEM, nBits) == false)
	{
		success = false;
		goto end;
	}

	pkey = opensslRsaKeyWrapper.getPkey();
	if(pkey == NULL)
	{
		success = false;
		goto end;
	}

	if(opensslRsaKeyWrapper.write(pkey, PKEY_TYPE_T::PKEY_PRIVATE_KEY, "", "") == false)
	{
		success = false;
		goto end;
	}

end:
	json = pbnjson::Object();

	if(success = false)
	{
        json.put("returnValue", false);
        json.put("errorText", "wrong of keyFilename or keySize");
	}
	else
	{
		json.put("KeyFilename", outputKeyFilename.c_str());
		json.put("keySize", nBits);
        json.put("returnValue", true);
	}

	result = pbnjson::JGenerator::serialize(json, pbnjson::JSchemaFragment("{}"));
	lsResponseMsg.respond(result.c_str());

	return success ? true : false;
#endif

	EVP_PKEY *pkey = NULL;

	if(outputKeyFilename.empty())
	{
		return false;
	}

	if(keySize <= 1024 || keySize >= 16384)
	{
		return false;
	}

	OpensslRsaKeyWrapper opensslRsaKeyWrapper;

	if(opensslRsaKeyWrapper.open(outputKeyFilename, 'w', FORMAT_PEM, keySize) == false)
	{
		return false;
	}

	pkey = opensslRsaKeyWrapper.getPkey();
	if(pkey == NULL)
	{
		return false;
	}

	if(opensslRsaKeyWrapper.write(pkey, PKEY_TYPE_T::PKEY_PRIVATE_KEY, "", "") == false)
	{
		return false;
	}
	
	return true;
}

bool CertificateManager::csr()
{
	 return true;
}

bool CertificateManager::sign()
{
	 return true;
}

bool CertificateManager::verify()
{
	 return true;
}
*/