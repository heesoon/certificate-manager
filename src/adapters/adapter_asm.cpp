#include "adapter_asm.hpp"
#include "logging.h"
#include <pbnjson.hpp>

#define URI_ASM_GET_LISTDEVICES "luna://com.webos.service.attachedstoragemanager/listDevices"
AdapterAsm *AdapterAsm::_instance = nullptr;

AdapterAsm* AdapterAsm::getInstance()
{
    if(_instance == nullptr)
    {
        return nullptr;
    }

    return _instance;
}

AdapterAsm::AdapterAsm(LS::Handle *handle, std::string serviceName) :
    mServiceName(serviceName), mLunaClient(*handle),
    mAsmGetDeviceListSubscription(mLunaClient),
    mCallToken(0)
{
    if(_instance == nullptr)
    {
        _instance = this;
    }

    pbnjson::JValue sendObj = pbnjson::JObject{{"subscribe", true}};
    //pbnjson::JValue sendObj = pbnjson::JObject{{"deviceType" : "usb", "subscribe" : true}};
    mAsmGetDeviceListSubscription.subscribe(
        URI_ASM_GET_LISTDEVICES, //
        sendObj, this,
        &AdapterAsm::AsmGetDeviceListSubscriptionCb
    );
}

void AdapterAsm::AsmGetDeviceListSubscriptionCb(LSUtils::LunaResponse &response)
{
	LOG_DEBUG("AsmGetDeviceListSubscriptionCb star....");

	if(!response.isSuccess())
    {
        return;
    }

    pbnjson::JValue json = response.getJson();

    if(!json.hasKey("returnValue") || json["returnValue"].asBool() == false)
    {
        return;
    }

    // get devices array
    pbnjson::JValue devices = json["devices"];
    for(ssize_t i = 0; i < devices.arraySize(); i++)
    {
        // get device object
        pbnjson::JValue device = devices[i];
        std::string deviceType = device["deviceType"].asString();

		LOG_DEBUG("deviceType %s ", deviceType.c_str());

        if(deviceType != "usb")
        {
            continue;
        }

        // get subDevice array
        pbnjson::JValue subDevices = device["subDevices"];
        for(ssize_t j = 0; j < subDevices.arraySize(); j++)
        {
            pbnjson::JValue subDevice = subDevices[j];
            std::string deviceUri = subDevice["deviceUri"].asString();
			LOG_DEBUG("deviceUri %s ", deviceUri.c_str());
            mDeviceUris.emplace_back(deviceUri);
        }
    }

	LOG_DEBUG("AsmGetDeviceListSubscriptionCb finish....");
}

AdapterAsm::~AdapterAsm()
{
    mAsmGetDeviceListSubscription.cancel();
}

#if 0
static bool backup_getStoragePath(LSHandle *sh, const char *serviceName, bool connected, void *ctx)
{
    if (connected)
    {
        LSError lsError;
        LSErrorInit(&lsError);
        if (!LSCall(g_lsServiceHandle,
                "luna://com.webos.service.attachedstoragemanager/listDevices",
                "{\"deviceType\":[\"usb\"], \"subscribe\":true}",
                backup_getStoragePathCallback,
                NULL,
                NULL,
                &lsError))
        {
            FilePrint("[ERROR] LSCall returns false when calling attachedstoragemanager/listDevices. error message : %s", lsError.message);
            LSErrorFree(&lsError);
        }
    }

    return true;
}
#endif