#include "a_storageAdapter.hpp"
#include <pbnjson.hpp>

#define URI_STORAGE_GET_LISTDEVICES "luna://com.webos.service.attachedstoragemanager/listDevices"

StorageAdapter *StorageAdapter::_instance = nullptr;
StorageAdapter* StorageAdapter::getInstance()
{
    if(_instance == nullptr)
    {
        return nullptr;
    }

    return _instance;
}

StorageAdapter::StorageAdapter(LS::Handle *handle, std::string serviceName) :
    m_serviceName(serviceName), m_lunaClient(*handle),
    m_getStorageDevicePathSubscription(m_lunaClient),
    m_callToken(0)
{
    if(_instance == nullptr)
    {
        _instance = this;
    }

    pbnjson::JValue sendObj = pbnjson::JObject{{"subscribe", true}};
    //pbnjson::JValue sendObj = pbnjson::JObject{{"deviceType" : "usb", "subscribe" : true}};
    m_getStorageDevicePathSubscription.subscribe(
        URI_STORAGE_GET_LISTDEVICES, //
        sendObj, this,
        &StorageAdapter::getStorageDevicePathSubscriptionCb
    );
}

void StorageAdapter::getStorageDevicePathSubscriptionCb(LSUtils::LunaResponse &response)
{
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
            m_deviceUris.emplace_back(deviceUri);
        }
    }
}

StorageAdapter::~StorageAdapter()
{
    m_getStorageDevicePathSubscription.cancel();
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