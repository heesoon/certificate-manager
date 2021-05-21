#include "CertificateManager.hpp"
#include "Log.hpp"
#include <JUtil.hpp>
#include <pbnjson.hpp>

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
    //LSErrorSafe lserror;
    //bool subscribed = false;

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