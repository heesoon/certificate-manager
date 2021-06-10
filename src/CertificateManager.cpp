#include "CertificateManager.hpp"
#include "OpensslRsaKeyWrapper.hpp"
#include "lunaservice_utils.h"
#include <JUtil.hpp>
#include <pbnjson.hpp>
#include <string>

const std::string service = "com.webos.service.certificatemanager";
CertificateManager::CertificateManager(LSUtils::LunaService &service)
{
	LOG_INFO(MSGID_MAINAPP, 0, "CertificateManager start");

	service.registerMethod("/", "generateKey", 	this, &CertificateManager::generateKey);
	service.registerMethod("/", "csr", 			this, &CertificateManager::csr);
	service.registerMethod("/", "sign", 		this, &CertificateManager::sign);
	service.registerMethod("/", "verify", 		this, &CertificateManager::verify);
}

pbnjson::JValue CertificateManager::generateKey(LSUtils::LunaRequest &message)
{
	bool success = true;
	int nBits = 0;
	EVP_PKEY *pkey = NULL;
	std::string result = "";
	std::string outputKeyFilename = "";
	pbnjson::JValue json;
	pbnjson::JValue request;
	OpensslRsaKeyWrapper opensslRsaKeyWrapper;

	request = pbnjson::Object();
	request = message.getJson();

	LOG_INFO(MSGID_MAINAPP, 0, "[%s][%d]message (%s)", __func__, __LINE__,request.stringify().c_str());

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

	return json;
}

pbnjson::JValue CertificateManager::csr(LSUtils::LunaRequest &message)
{
	bool ret = true;
	 //LS::Message request(&message);
	 //request.respond(R"json({"bus":"public"})json");
	 return pbnjson::JObject{
        {"returnValue", ret}
    };
}

pbnjson::JValue CertificateManager::sign(LSUtils::LunaRequest &message)
{
	bool ret = true;
	 //LS::Message request(&message);
	 //request.respond(R"json({"bus":"public"})json");
	 LOG_INFO(MSGID_MAINAPP, 0, "<%s>[%s:%d]", __FILE__,__func__, __LINE__);
	 return pbnjson::JObject{
        {"returnValue", ret}
    };
}

pbnjson::JValue CertificateManager::verify(LSUtils::LunaRequest &message)
{
	bool ret = true;
	 //LS::Message request(&message);
	 //request.respond(R"json({"bus":"public"})json");
	LOG_INFO(MSGID_MAINAPP, 0, "[%s][%d]", __func__, __LINE__);
	return pbnjson::JObject{
        {"returnValue", ret}
    };
}