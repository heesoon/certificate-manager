#include <glib.h>
#include <string>
#include <PmLog.h>
#include <pbnjson.hpp>
#include <luna-service2/lunaservice.h>
#include "CertificateManager.hpp"

const std::string serviceName = "com.webos.service.certificatemanager";

static bool generateKey(LSHandle *sh, LSMessage* message, void* ctx)
{
    bool success = true;
	int keySize = 0;
	std::string outputKeyFilename = "";
    std::string errorText = "";
	pbnjson::JValue request;
    pbnjson::JValue reply = pbnjson::Object();;
    pbnjson::JDomParser parser(NULL);
    pbnjson::JSchemaFragment schema("{}");
    CertificateManager certificateManager;
	LSError lserror;
	LSErrorInit(&lserror);
    
    const char *payload = LSMessageGetPayload(message);
    if(!parser.parse(payload, schema))
    {
        success = false;
        errorText = "schema parsing error";
		goto end;
    }

    request = parser.getDom();
    outputKeyFilename = request["KeyFilename"].asString();
	if(outputKeyFilename.empty())
	{
        success = false;
        errorText = "wrong keyfile name or path";
		goto end;
	}

	keySize = request["keySize"].asNumber<int>();
	if(keySize <= 1024 || keySize >= 16384)
	{
        success = false;
        errorText = "keysize out of range(1024 ~ 16384";
		goto end;
	}

    if(certificateManager.generateKey(outputKeyFilename, keySize) == false)
    {
        success = false;
        errorText = "certificateManager function error";
		goto end;
    }

end:

    if(success == true)
    {
        reply.put("KeyFilename", outputKeyFilename.c_str());
        reply.put("keySize", keySize);
        reply.put("returnValue", true);
    }
    else
    {
        reply.put("returnValue", false);
        reply.put("errorText", errorText.c_str());
    }

    if(!LSMessageReply(sh, message, reply.stringify().c_str(), &lserror))
    {
        LSErrorPrint(&lserror, stderr);
        return false;
    }

    if (LSErrorIsSet(&lserror))
    {
        LSErrorFree(&lserror);
    }

    return success ? true : false;
}

static bool csr(LSHandle *sh, LSMessage* message, void* ctx)
{
    bool success = true;
	std::string outputCsrFilename = "";
	std::string inputPrivateKey = "";
	std::string commonName = "";
    std::string errorText = "";
	pbnjson::JValue request;
    pbnjson::JValue reply = pbnjson::Object();;
    pbnjson::JDomParser parser(NULL);
    pbnjson::JSchemaFragment schema("{}");
    CertificateManager certificateManager;
	LSError lserror;
	LSErrorInit(&lserror);
    
    const char *payload = LSMessageGetPayload(message);
    if(!parser.parse(payload, schema))
    {
        success = false;
        errorText = "schema parsing error";
		goto end;
    }

    request = parser.getDom();
    outputCsrFilename = request["csrFilename"].asString();
	if(outputCsrFilename.empty())
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

    commonName = request["commonName"].asString();
	if(commonName.empty())
	{
        success = false;
        errorText = "empty common name";
		goto end;
	}

    if(certificateManager.csr(outputCsrFilename, inputPrivateKey, commonName) == false)
    {
        success = false;
        errorText = "certificateManager csr function error";
		goto end;
    }

end:

    if(success == true)
    {
        reply.put("outputCsrFilename", outputCsrFilename.c_str());
        reply.put("returnValue", true);
    }
    else
    {
        reply.put("returnValue", false);
        reply.put("errorText", errorText.c_str());
    }

    if(!LSMessageReply(sh, message, reply.stringify().c_str(), &lserror))
    {
        LSErrorPrint(&lserror, stderr);
        return false;
    }

    if (LSErrorIsSet(&lserror))
    {
        LSErrorFree(&lserror);
    }

    return success ? true : false;
}

static bool sign(LSHandle *sh, LSMessage* message, void* ctx)
{
    bool success = true;
	std::string outputCertFilename = "";
	std::string inputCsrFilename = "";

    std::string errorText = "";
	pbnjson::JValue request;
    pbnjson::JValue reply = pbnjson::Object();;
    pbnjson::JDomParser parser(NULL);
    pbnjson::JSchemaFragment schema("{}");
    CertificateManager certificateManager;
	LSError lserror;
	LSErrorInit(&lserror);
    
    const char *payload = LSMessageGetPayload(message);
    if(!parser.parse(payload, schema))
    {
        success = false;
        errorText = "schema parsing error";
		goto end;
    }

    request = parser.getDom();
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

    if(certificateManager.sign(outputCertFilename, inputCsrFilename) == false)
    {
        success = false;
        errorText = "certificateManager sign function error";
		goto end;
    }

end:

    if(success == true)
    {
        reply.put("outputCertFilename", outputCertFilename.c_str());
        reply.put("returnValue", true);
    }
    else
    {
        reply.put("returnValue", false);
        reply.put("errorText", errorText.c_str());
    }

    if(!LSMessageReply(sh, message, reply.stringify().c_str(), &lserror))
    {
        LSErrorPrint(&lserror, stderr);
        return false;
    }

    if (LSErrorIsSet(&lserror))
    {
        LSErrorFree(&lserror);
    }

    return success ? true : false;
}

static bool verify(LSHandle *sh, LSMessage* message, void* ctx)
{
    bool success = true;
	std::string inputCertFile = "";

    std::string errorText = "";
	pbnjson::JValue request;
    pbnjson::JValue reply = pbnjson::Object();;
    pbnjson::JDomParser parser(NULL);
    pbnjson::JSchemaFragment schema("{}");
    CertificateManager certificateManager;
	LSError lserror;
	LSErrorInit(&lserror);
    
    const char *payload = LSMessageGetPayload(message);
    if(!parser.parse(payload, schema))
    {
        success = false;
        errorText = "schema parsing error";
		goto end;
    }

    request = parser.getDom();
    inputCertFile = request["certFilename"].asString();
	if(inputCertFile.empty())
	{
        success = false;
        errorText = "empty certification file or path";
		goto end;
	}

    if(certificateManager.verify(inputCertFile) == false)
    {
        success = false;
        errorText = "certificateManager sign function error";
		goto end;
    }

end:

    if(success == true)
    {
        reply.put("inputCertFile", inputCertFile.c_str());
        reply.put("returnValue", true);
    }
    else
    {
        reply.put("returnValue", false);
        reply.put("errorText", errorText.c_str());
    }

    if(!LSMessageReply(sh, message, reply.stringify().c_str(), &lserror))
    {
        LSErrorPrint(&lserror, stderr);
        return false;
    }

    if (LSErrorIsSet(&lserror))
    {
        LSErrorFree(&lserror);
    }

    return success ? true : false;
}

static LSMethod serviceMethods[] = {
    { "generateKey", generateKey },
	{ "csr", csr },
	{ "sign", sign },
	{ "verify", verify }
};

int main(int argc, char* argv[])
{
    LSError lserror;
    LSErrorInit(&lserror);

    GMainLoop* mainLoop = g_main_loop_new(nullptr, false);
    LSHandle *m_handle = nullptr;

    if(!LSRegister(serviceName.c_str(), &m_handle, &lserror))
    {
        //PmLogError(getPmLogContext(), "LS_REGISTER", 0, "Unable to register to luna-bus");
        LSErrorPrint(&lserror, stdout);

        return false;
    }

    if (!LSRegisterCategory(m_handle, "/", serviceMethods, NULL, NULL, &lserror))
    {
        //PmLogError(getPmLogContext(), "LS_REGISTER", 0, "Unable to register category and method");
        LSErrorPrint(&lserror, stdout);

        return false;
    }

    if(!LSGmainAttach(m_handle, mainLoop, &lserror))
    {
        //PmLogError(getPmLogContext(), "LS_REGISTER", 0, "Unable to attach service");
        LSErrorPrint(&lserror, stdout);

        return false;
    }

    g_main_loop_run(mainLoop);

    if(!LSUnregister(m_handle, &lserror))
    {
        //PmLogError(getPmLogContext(), "LS_REGISTER", 0, "Unable to unregister service");
        LSErrorPrint(&lserror, stdout);

        return false;
    }

    g_main_loop_unref(mainLoop);
    mainLoop = nullptr;

    return 0;
}
