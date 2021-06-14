#include "CertificateManager.hpp"
#include "OpensslRsaKeyWrapper.hpp"
#include "OpensslCsrWrapper.hpp"
#include "OpensslCaWrapper.hpp"
#include "logging.h"
#include <string>

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
	std::string errorText = "";
	std::string result = "";
	std::string outputKeyFilename = "";

	pbnjson::JValue reply;
	pbnjson::JValue request = pbnjson::Object();
	request = message.getJson();

	LOG_INFO(MSGID_MAINAPP, 0, "[%s][%d]message (%s)", __func__, __LINE__,request.stringify().c_str());

	OpensslRsaKeyWrapper opensslRsaKeyWrapper;

	outputKeyFilename = request["KeyFilename"].asString();
	if(outputKeyFilename.empty())
	{
		success = false;
		errorText = "wrong keyfile name or path";
		goto end;
	}

	nBits = request["keySize"].asNumber<int>();
	if(nBits <= 1024 || nBits >= 16384)
	{
		success = false;
		errorText = "keysize out of range(1024 ~ 16384";
		goto end;
	}

	if(opensslRsaKeyWrapper.open(outputKeyFilename, 'w', FORMAT_PEM, nBits) == false)
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

end:
	reply = pbnjson::Object();

	if(success == false)
	{
        reply.put("returnValue", false);
        reply.put("errorText", errorText.c_str());
	}
	else
	{
		reply.put("KeyFilename", outputKeyFilename.c_str());
		reply.put("keySize", nBits);
        reply.put("returnValue", true);
	}

	return reply;
}

pbnjson::JValue CertificateManager::csr(LSUtils::LunaRequest &message)
{
	bool success = true;
	X509_REQ *x509Req = NULL;
	std::string errorText = "";
	std::string outputCsrFile = "";
	std::string inputPrivateKey = "";
	subject_t subject = {"", "KR", "Seoul", "Seoul", "IDSW R&D Division", "certificatemanger@idsw.lge.com"};
	const std::string inputConf = "/usr/palm/services/com.webos.service.certificatemanager/scripts/customer_openssl.cnf";

	pbnjson::JValue reply;
	pbnjson::JValue request = pbnjson::Object();
	request = message.getJson();

	LOG_INFO(MSGID_MAINAPP, 0, "[%s][%d]message (%s)", __func__, __LINE__,request.stringify().c_str());

	OpensslCsrWrapper opensslCsrWrapper;

	outputCsrFile = request["csrFilename"].asString();
	if(outputCsrFile.empty())
	{
		success = false;
		errorText = "empty csr file or path";
		goto end;
	}

	inputPrivateKey = request["privateKey"].asString();
	if(inputPrivateKey.empty())
	{
		success = false;
		errorText = "empty private key file or path";
		goto end;
	}

	subject.commonName = request["commonName"].asString();
	if(subject.commonName.empty())
	{
		success = false;
		errorText = "empty common name";
		goto end;
	}

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
	reply = pbnjson::Object();

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

pbnjson::JValue CertificateManager::sign(LSUtils::LunaRequest &message)
{
	bool success = true;
	X509 *x509 = NULL;

	std::string errorText = "";
	std::string outputCertFilename = "";
	std::string inputCsrFilename = "";
	const std::string inputConfigFile = "/usr/palm/services/com.webos.service.certificatemanager/scripts/customer_openssl.cnf";

	pbnjson::JValue reply;
	pbnjson::JValue request = pbnjson::Object();
	request = message.getJson();

	LOG_INFO(MSGID_MAINAPP, 0, "[%s][%d]message (%s)", __func__, __LINE__,request.stringify().c_str());

	OpensslCaWrapper opensslCaWrapper;

	outputCertFilename = request["certFilename"].asString();
	if(outputCertFilename.empty())
	{
		success = false;
		errorText = "empty certification file or path";
		goto end;
	}

	inputCsrFilename = request["csrFilename"].asString();
	if(inputCsrFilename.empty())
	{
		success = false;
		errorText = "empty csr file or path";
		goto end;
	}

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
	reply = pbnjson::Object();

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

pbnjson::JValue CertificateManager::verify(LSUtils::LunaRequest &message)
{
	bool success = true;
	std::string errorText = "";
	std::string inputCertFile = "";
	const std::string inputCaChainFile = "/usr/palm/services/com.webos.service.certificatemanager/scripts/ca-chain.cert.pem";

	pbnjson::JValue reply;
	pbnjson::JValue request = pbnjson::Object();
	request = message.getJson();

	OpensslCaWrapper opensslCaWrapper;

	inputCertFile = request["certFilename"].asString();
	if(inputCertFile.empty())
	{
		success = false;
		errorText = "empty certification file or path";
		goto end;
	}

	if(opensslCaWrapper.verifyByCa(inputCaChainFile, inputCertFile) == false)
	{
		success = false;
		errorText = "verify x509 error";
		goto end;
	}

end:
	reply = pbnjson::Object();

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
