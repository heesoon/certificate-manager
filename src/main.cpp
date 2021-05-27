#include <glib.h>
#include <string>
#include <luna-service2/lunaservice.h>
#include <PmLog.h>
#include <pbnjson.hpp>
#include "CertificateManager.hpp"

const std::string serviceName = "com.webos.service.certificatemanager";

static bool generateKey(LSHandle *sh, LSMessage* message, void* ctx)
{
#if 0	
    //PmLogInfo(getPmLogContext(), "HANDLE_HELLO", 0, "hello method called");

    pbnjson::JValue reply = pbnjson::Object();
    if (reply.isNull())
        return false;

    reply.put("returnValue", true);
    reply.put("answer", "Hello, Native Service!!");

    LSError lserror;
    LSErrorInit(&lserror);

    if (!LSMessageReply(sh, message, reply.stringify().c_str(), &lserror))
    {
        //PmLogError(getPmLogContext(), "HANDLE_HELLO", 0, "Message reply error!!");
        LSErrorPrint(&lserror, stdout);

        return false;
    }
    return true;
#endif
	bool success = true;
	unsigned int keySize = 0;
	std::string outputKeyFilename = "";
	CertificateManager certificateManager;
	pbnjson::JValue request;
}

static bool csr(LSHandle *sh, LSMessage* message, void* ctx)
{
    //PmLogInfo(getPmLogContext(), "HANDLE_HELLO", 0, "hello method called");

    pbnjson::JValue reply = pbnjson::Object();
    if (reply.isNull())
        return false;

    reply.put("returnValue", true);
    reply.put("answer", "Hello, Native Service!!");

    LSError lserror;
    LSErrorInit(&lserror);

    if (!LSMessageReply(sh, message, reply.stringify().c_str(), &lserror))
    {
        //PmLogError(getPmLogContext(), "HANDLE_HELLO", 0, "Message reply error!!");
        LSErrorPrint(&lserror, stdout);

        return false;
    }
    return true;
}

static bool sign(LSHandle *sh, LSMessage* message, void* ctx)
{
    //PmLogInfo(getPmLogContext(), "HANDLE_HELLO", 0, "hello method called");

    pbnjson::JValue reply = pbnjson::Object();
    if (reply.isNull())
        return false;

    reply.put("returnValue", true);
    reply.put("answer", "Hello, Native Service!!");

    LSError lserror;
    LSErrorInit(&lserror);

    if (!LSMessageReply(sh, message, reply.stringify().c_str(), &lserror))
    {
        //PmLogError(getPmLogContext(), "HANDLE_HELLO", 0, "Message reply error!!");
        LSErrorPrint(&lserror, stdout);

        return false;
    }
    return true;
}

static bool verify(LSHandle *sh, LSMessage* message, void* ctx)
{
    //PmLogInfo(getPmLogContext(), "HANDLE_HELLO", 0, "hello method called");

    pbnjson::JValue reply = pbnjson::Object();
    if (reply.isNull())
        return false;

    reply.put("returnValue", true);
    reply.put("answer", "Hello, Native Service!!");

    LSError lserror;
    LSErrorInit(&lserror);

    if (!LSMessageReply(sh, message, reply.stringify().c_str(), &lserror))
    {
        //PmLogError(getPmLogContext(), "HANDLE_HELLO", 0, "Message reply error!!");
        LSErrorPrint(&lserror, stdout);

        return false;
    }
    return true;
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