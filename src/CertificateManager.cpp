#include <string>
#include "CertificateManager.hpp"
#include "OpensslRsaKeyWrapper.hpp"
#include "OpensslCsrWrapper.hpp"
#include "OpensslCaWrapper.hpp"
#include "logging.h"

#include "adapter_db.hpp"

const std::string temporalLocalStorage = "/usr/palm/services/com.webos.service.certificatemanager";

CertificateManager::CertificateManager(LSUtils::LunaService &service)
{
	LOG_INFO(MSGID_MAINAPP, 0, "CertificateManager start");

	service.registerMethod("/", "generateKey", 	this, &CertificateManager::generateKey);
	service.registerMethod("/", "csr", 			this, &CertificateManager::csr);
	service.registerMethod("/", "sign", 		this, &CertificateManager::sign);
	service.registerMethod("/", "verify", 		this, &CertificateManager::verify);
}

bool CertificateManager::getKeyId(LSUtils::LunaRequest &request, const std::string &keyname, std::string &keyId)
{
	std::string appId = "";
	std::string applicationId 	= request.getApplicationID();
	std::string senderId 		= request.getSender();

	if(applicationId != "UNKNOWN")
	{
		appId = applicationId;
	}
	else if(senderId != "UNKNOWN")
	{
		appId = senderId;
	}
	else
	{
		appId = "UNKNOWN";
		return false;
	}

	//keyId = appId + "::" + keyname;
	keyId = "com.webos.service.certificateTest::" + keyname;

#if 1
	LOG_INFO("AdapterDb", 0, "applicationId = %s ..", applicationId.c_str());
	LOG_INFO("AdapterDb", 0, "senderId = %s ..", senderId.c_str());
	LOG_INFO("AdapterDb", 0, "serviceName = %s ..", request.getSenderServiceName().c_str());
	LOG_INFO("AdapterDb", 0, "getKeyId = %s ..", keyId.c_str());
#endif

	return true;
}

pbnjson::JValue CertificateManager::generateKey(LSUtils::LunaRequest &request)
{
	LOG_INFO(MSGID_MAINAPP, 0, "[%s][%d]", __func__, __LINE__);

	bool success = true;
	int keySize = 0;
	std::string keyId = "";
	std::string errorText = "";
	std::string keyname = "";
	std::string outputKeyFilename = "";

	EVP_PKEY *pkey = NULL;
	OpensslRsaKeyWrapper opensslRsaKeyWrapper;

	if(AdapterDb::getInstance() == nullptr)
	{
		success = false;
		errorText = "db8 is not initialized";
		goto end;
	}

	if( request.hasKey("keyname") == false ||
		request.hasKey("KeyFilename") == false || 
		request.hasKey("keySize") == false )
	{
		success = false;
		errorText = "empty of keyname or KeyFilename or keySize in luna";
		goto end;
	}

	request.param("keyname", keyname);
	request.param("KeyFilename", outputKeyFilename);
	request.param("keySize", keySize);

	if(getKeyId(request, keyname, keyId) == false)
	{
		success = false;
		errorText = "wrong request (No Keyname)";
		goto end;
	}

	// check key data whether key is already generated or not
	if(AdapterDb::getInstance()->findKey(keyId) == true)
	{
		success = false;
		errorText = "key already exist";
		goto end;
	}

/*
	if(keySize <= 1024 || keySize >= 16384)
	{
		success = false;
		errorText = "keySize out of range(1024 ~ 16384";
		goto end;
	}
*/
	if(opensslRsaKeyWrapper.open(outputKeyFilename, 'w', FORMAT_PEM, keySize) == false)
	{
		success = false;
		errorText = "file open error";
		goto end;
	}

	pkey = opensslRsaKeyWrapper.getPkey();
	if(pkey == NULL)
	{
		success = false;
		errorText = "get key error";
		goto end;
	}

	if(opensslRsaKeyWrapper.write(pkey, PKEY_TYPE_T::PKEY_PRIVATE_KEY, "", "") == false)
	{
		success = false;
		errorText = "write key error";
		goto end;
	}

	// update Db
	if(AdapterDb::getInstance()->put(keyId) == false)
	{
		success = false;
		errorText = "failed to update db";
		goto end;
	}

end:

	pbnjson::JValue reply = pbnjson::Object();

	if(success == false)
	{
        reply.put("returnValue", false);
        reply.put("errorText", errorText.c_str());
	}
	else
	{
		reply.put("KeyFilename", outputKeyFilename.c_str());
		reply.put("keySize", keySize);
        reply.put("returnValue", true);
	}

	return reply;
}

pbnjson::JValue CertificateManager::csr(LSUtils::LunaRequest &request)
{
	LOG_INFO(MSGID_MAINAPP, 0, "[%s][%d]", __func__, __LINE__);

	bool success = true;
	X509_REQ *x509Req = NULL;
	std::string errorText = "";
	std::string outputCsrFile = "";
	std::string inputPrivateKey = "";
	//subject_t subject = {"", "KR", "Seoul", "Seoul", "IDSW R&D Division", "certificatemanger@idsw.lge.com"};

	subject_t subject;
	subject.countryName 		= "KR";
	subject.stateOrProvinceName	= "Seoul";
	subject.localityName		= "Seoul";
	subject.organizationName	= "IDSW R&D Division";
	subject.emailAddress		= "rnd@support.com";

	const std::string inputConf = temporalLocalStorage + "/scripts/customer_openssl.cnf";

	OpensslCsrWrapper opensslCsrWrapper;

	if( request.hasKey("csrFilename") == false || request.hasKey("privateKey") == false || request.hasKey("commonName") == false )
	{
		success = false;
		errorText = "empty of csrFilename, privateKey or commonName in luna";
		goto end;
	}

	request.param("csrFilename", outputCsrFile);
	request.param("privateKey", inputPrivateKey);
	request.param("commonName", subject.commonName);

	if(opensslCsrWrapper.open(outputCsrFile, 'w', FORMAT_PEM) == false)
	{
		success = false;
		errorText = "csr file open error";
		goto end;
	}

	if(opensslCsrWrapper.makeCsr(inputConf, inputPrivateKey, subject) == false)
	{
		success = false;
		errorText = "make csr error";
		goto end;
	}

	x509Req = opensslCsrWrapper.getX509Req();
	if(x509Req == NULL)
	{
		success = false;
		errorText = "get x509Req error";
		goto end;
	}

	if(opensslCsrWrapper.write(x509Req) == false)
	{
		success = false;
		errorText = "write x509Req error";
		goto end;
	}

end:

	pbnjson::JValue reply = pbnjson::Object();

	if(success == false)
	{
        reply.put("returnValue", false);
        reply.put("errorText", errorText.c_str());
	}
	else
	{
		reply.put("outputCsrFile", outputCsrFile.c_str());
        reply.put("returnValue", true);
	}

	return reply;
}

pbnjson::JValue CertificateManager::sign(LSUtils::LunaRequest &request)
{
	LOG_INFO(MSGID_MAINAPP, 0, "[%s][%d]", __func__, __LINE__);

	bool success = true;
	X509 *x509 = NULL;

	std::string errorText = "";
	std::string outputCertFilename = "";
	std::string inputCsrFilename = "";
	const std::string inputConfigFile = temporalLocalStorage + "/scripts/customer_openssl.cnf";

	OpensslCaWrapper opensslCaWrapper;

	if( request.hasKey("certFilename") == false || request.hasKey("csrFilename") == false )
	{
		success = false;
		errorText = "empty of certFilename or csrFilename in luna";
		goto end;
	}

	request.param("certFilename", outputCertFilename);
	request.param("csrFilename", inputCsrFilename);

	if(opensslCaWrapper.open(outputCertFilename, 'w', FORMAT_PEM) == false)
	{
		success = false;
		errorText = "certificate file open error";
		goto end;
	}

	if(opensslCaWrapper.generateCertSignedByCa(inputConfigFile, inputCsrFilename) == false)
	{
		success = false;
		errorText = "certificate sign error";
		goto end;
	}

	x509 = opensslCaWrapper.getX509();
	if(x509 == NULL)
	{
		success = false;
		errorText = "get x509 error";
		goto end;
	}

	if(opensslCaWrapper.write(x509) == false)
	{
		success = false;
		errorText = "write x509 error";
		goto end;
	}

end:

	pbnjson::JValue reply = pbnjson::Object();
	if(success == false)
	{
		reply.put("returnValue", false);
		reply.put("errorText", errorText.c_str());
	}
	else
	{
		reply.put("outputCertFilename", outputCertFilename.c_str());
		reply.put("returnValue", true);
	}

	return reply;
}

pbnjson::JValue CertificateManager::verify(LSUtils::LunaRequest &request)
{
	LOG_INFO(MSGID_MAINAPP, 0, "[%s][%d]", __func__, __LINE__);

	bool success = true;
	std::string errorText = "";
	std::string inputCertFile = "";
	const std::string inputCaChainFile = temporalLocalStorage + "/scripts/ca-chain.cert.pem";

	OpensslCaWrapper opensslCaWrapper;

	if( request.hasKey("certFilename") == false)
	{
		success = false;
		errorText = "empty of certFilename in luna";
		goto end;
	}

	request.param("certFilename", inputCertFile);

	if(opensslCaWrapper.verifyByCa(inputCaChainFile, inputCertFile) == false)
	{
		success = false;
		errorText = "verify x509 error";
		goto end;
	}

end:

	pbnjson::JValue reply = pbnjson::Object();
	if(success == false)
	{
		reply.put("returnValue", false);
		reply.put("errorText", errorText.c_str());
	}
	else
	{
		reply.put("inputCertFile", inputCertFile.c_str());
		reply.put("returnValue", true);
	}

	return reply;
}
