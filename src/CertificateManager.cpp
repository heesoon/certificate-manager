#include "CertificateManager.hpp"
#include "OpensslRsaKeyWrapper.hpp"
#include "Log.hpp"
#include <JUtil.hpp>
#include <pbnjson.hpp>
#include <string>

const std::string service = "com.webos.service.certificateManager";
CertificateManager::CertificateManager() : LS::Handle(LS::registerService(service.c_str()))
{
	LS_CATEGORY_BEGIN(CertificateManager, "/")
		LS_CATEGORY_METHOD(generateKey)
		LS_CATEGORY_METHOD(csr)
		LS_CATEGORY_METHOD(sign)
		LS_CATEGORY_METHOD(verify)
	LS_CATEGORY_END

	//attach to mainloop and run it
	attachToLoop(upGmainLoop.get());
	// run the gmainloop
	g_main_loop_run(upGmainLoop.get());
}

bool CertificateManager::generateKey(LSMessage &message)
{
    LSErrorSafe lserror;
    //bool subscribed = false;
	bool success = true;
	std::string outputKeyFilename = "";
	int nBits = 0;
	EVP_PKEY *pkey = NULL;

	auto *appid = LSMessageGetApplicationID(&message);
	auto servicename = LSMessageGetSenderServiceName(&message);
	auto *method = LSMessageGetMethod(&message);
	auto *category = LSMessageGetCategory(&message);


    LOG_INFO(MSGID_GENERATOR_KEY, 4,
        PMLOGKS("appid", appid),
        PMLOGKS("servicename", servicename),
        PMLOGKS("method", method),
        PMLOGKS("category", category), " ");

	//if (LSMessageIsSubscription(&message))
	//	subscribed = LSSubscriptionProcess(lshandle, &message, &subscribed, &lserror);

    pbnjson::JValue request = pbnjson::Object();
    request = JUtil::parse(LSMessageGetPayload(&message), "", nullptr);

	outputKeyFilename = request['outputKeyFilename'].asString();
	if(keyOutPath.empty())
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

	OpensslRsaKeyWrapper opensslRsaKeyWrapper;
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

	pbnjson::JValue json = pbnjson::Object();

end:

	return true;
}

bool CertificateManager::csr(LSMessage &message)
{
	 //LS::Message request(&message);
	 //request.respond(R"json({"bus":"public"})json");
	 return true;
}

bool CertificateManager::sign(LSMessage &message)
{
	 //LS::Message request(&message);
	 //request.respond(R"json({"bus":"public"})json");
	 return true;
}

bool CertificateManager::verify(LSMessage &message)
{
	 //LS::Message request(&message);
	 //request.respond(R"json({"bus":"public"})json");
	 return true;
}