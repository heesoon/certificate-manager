#include "adapter_asm.hpp"
#include "logging.h"

#define URI_ASM_METHOD_LISTDEVICES "luna://com.webos.service.attachedstoragemanager/listDevices"
AdapterAsm *AdapterAsm::_instance = nullptr;

AdapterAsm* AdapterAsm::getInstance()
{
    if(_instance == nullptr)
    {
        return nullptr;
    }

    return _instance;
}

#if 0
AdapterAsm::AdapterAsm(LS::Handle *handle, std::string serviceName) :
    mServiceName(serviceName), mLunaClient(*handle),
    mStatusSubscription(mLunaClient),
    mCallToken(0)
{
    if(_instance == nullptr)
    {
        _instance = this;
    }
}
#else
AdapterAsm::AdapterAsm(LS::Handle *handle, std::string serviceName) :
    mServiceName(serviceName), mLunaClient(*handle),
    mStatusSubscription(mLunaClient)
{
    if(_instance == nullptr)
    {
        _instance = this;
    }

	//listDevices();
}
#endif

bool AdapterAsm::listDevices()
{
#if 1
    if(_instance == nullptr)
    {
        return false;
    }

    pbnjson::JValue jArray = pbnjson::Array();
    jArray.append("usb");
    pbnjson::JValue sendObj = pbnjson::JObject{{"deviceType", jArray}, {"subscribe", true}};

    mStatusSubscription.subscribe(
        URI_ASM_METHOD_LISTDEVICES,
        sendObj, this,
        &AdapterAsm::listDevicesCb
    );
#else
    pbnjson::JValue jArray = pbnjson::Array();
    jArray.append("usb");
    pbnjson::JValue sendObj = pbnjson::JObject{{"deviceType", jArray}, {"subscribe", true}};
	mCallToken = mLunaClient.callMultiReply(URI_ASM_GET_LISTDEVICES, sendObj, this, &AdapterAsm::AsmGetDeviceListSubscriptionCb);
#endif

	return true;
}

void AdapterAsm::listDevicesCb(LSUtils::LunaResponse &response)
{
	LOG_INFO("AdapterAsm", 0, "listDevicesCb start ..");

	std::unique_lock<std::mutex> lock(mMutex);

	if(response.isSuccess() == false)
    {
    	LOG_ERROR(MSGID_LS2_INVALID_RESPONSE, 0, "[%s, %d] returnValue is error", __FUNCTION__, __LINE__);
        return;
    }

	pbnjson::JValue json = response.getJson();
    if(!json.hasKey("returnValue") || json["returnValue"].asBool() == false)
    {
    	LOG_ERROR(MSGID_LS2_INVALID_RESPONSE, 0, "[%s, %d] returnValue is error", __FUNCTION__, __LINE__);
        return;
    }

	// clear device list
	mDeviceUris.clear();

	if(json.hasKey("devices") && json["devices"].isArray())
	{
		// get devices list array
	    pbnjson::JValue devices = json["devices"];

		for(ssize_t i = 0; i < devices.arraySize(); i++)
	 	{
	 		pbnjson::JValue device = devices[i];
			if(device.hasKey("subDevices") && device["subDevices"].isArray())
			{
				// get subDevice list array
        		pbnjson::JValue subDevices = device["subDevices"];
				for(ssize_t j = 0; j < subDevices.arraySize(); j++)
				{
		            pbnjson::JValue subDevice = subDevices[j];
		            std::string deviceUri = subDevice["deviceUri"].asString();
					if(deviceUri.empty() == true)
					{
						continue;
					}

					//LOG_DEBUG("deviceUri %s ", deviceUri.c_str());
					//LOG_INFO("AdapterAsm", 0, "[%s, %d] path = %s ", __FUNCTION__, __LINE__, deviceUri.c_str());
		            mDeviceUris.emplace_back(deviceUri);					
				}
			}
	 	}
	}

	LOG_INFO("AdapterAsm", 0, "listDevicesCb finish ..");
}

/*
void AdapterAsm::registerServiceStatus()
{
    LOG_INFO("AdapterAsm", 0, "registerServiceStatus start ..");
	const char *uri = "luna://com.palm.bus/signal/registerServerStatus";
	pbnjson::JValue json = pbnjson::JObject{{"serviceName", "com.webos.service.attachedstoragemanager"}};

    if(!mAsmStatusCheckStarted)
    {
    	mServiceStatusCall mLunaClient.callMultiReply(uri, json, this, &AdapterAsm::registerServiceStatusCb);
        mAsmStatusCheckStarted = true;
    }
}

void AdapterAsm::registerServiceStatusCb(LSUtils::LunaResponse &response)
{
	
}
*/

AdapterAsm::~AdapterAsm()
{
    mStatusSubscription.cancel();
    if(_instance != nullptr)
    {
        _instance = nullptr;
    }
}
