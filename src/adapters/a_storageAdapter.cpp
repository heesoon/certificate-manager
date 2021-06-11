#include "a_storageAdapter.hpp"
#include <pbnjson.hpp>

#define URI_STORAGE_GET_LISTDEVICES "luna://com.webos.service.attachedstoragemanager/listDevices"

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
        &StorageAdapter::getStorageDevicePathSubscriptionCb);
    );
}

StorageAdapter::~StorageAdapter()
{
    m_getStorageDevicePathSubscription.cancel();
}

void StorageAdapter::getStorageDevicePathSubscriptionCb(LSUtils::LunaResponse &response)
{
    if(!response.isSuccess())
    {
        return;
    }

    pbnjson::JValue res = response.getJson();

    if(!res.hasKey("returnValue") || res["returnValue"].asBool() == false)
    {
        return;
    }

    pbnjson::JValue::ObjectIterator iter;
    // device arrary
    pbnjson::JValue deviceLists = res["devices"];

    if(deviceLists.isArray())
    {
        for (iter = deviceLists.begin(); iter != deviceLists.end(); iter++)
        {
            pbnjson::JValue subDevices = (*iter)["subDevices"];
            std::string deviceType = (*iter)["deviceType"].asString();

            if(deviceType != "usb")
            {
                continue;
            }

            if(subDevices.isArray())
            {
                pbnjson::JValue::ObjectIterator jter;
                for (jter = subDevices.begin(); jter != subDevices.end(); jter++)
                {
                    pbnjson::JValue deviceUri = (*jter);
                    if(deviceUri.isString())
                    {
                        deviceUris.emplace_back(deviceUri.asString());
                    }
                }
            }
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