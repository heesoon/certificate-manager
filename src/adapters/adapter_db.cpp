#include "adapter_db.hpp"
#include "logging.h"
#include "json_payload.hpp"
#include "Utils.h"

#define LS_CALL_WAIT_TIMEOUT_DB8	15000
#define CM_DB8_KIND					"com.webos.service.certificatemanager:1"
#define CM_DB8_OWNER				"com.webos.service.certificatemanager"

AdapterDb *AdapterDb::_instance = nullptr;

AdapterDb* AdapterDb::getInstance()
{
    if(_instance == nullptr)
    {
        return nullptr;
    }

    return _instance;
}

AdapterDb::AdapterDb(LS::Handle *handle, std::string serviceName) :
    mServiceName(serviceName), mLunaClient(*handle),
    mStatusSubscription(mLunaClient),
    handle_(*handle)
{
    if(_instance == nullptr)
    {
        _instance = this;
    }
}

bool AdapterDb::findKey(const std::string &keyId)
{
	LOG_INFO("AdapterDb", 0, "findKey start ..");

	bool returnValue = false;
	int32_t count = 0;
	LS::Call call;
	LS_PLD::JSONPayload payload;

	pbnjson::JValue where 		= pbnjson::Object();
	pbnjson::JValue whereArr 	= pbnjson::Array();
	pbnjson::JValue query 		= pbnjson::Object();
	pbnjson::JValue sendObj 	= pbnjson::Object();

	// build where json object
	where.put("prop", "keyid");
	where.put("op", "=");
	where.put("val", keyId);

	// build query json object
	query.put("from", CM_DB8_KIND);
	whereArr.append(where);
	query.put("where", whereArr);
	query.put("limit", 1);
	
	// build sendObj json object
	sendObj.put("query", query);
	sendObj.put("count", true);

	// 1. call
	call = handle_.callOneReply(
		"luna://com.palm.db/find",
		sendObj.stringify().c_str());

	// 2. wait until timeout
	if(!checkLSMessageReply(call, payload, LS_CALL_WAIT_TIMEOUT_DB8))
	{
		return false;
	}

	payload.get("returnValue", returnValue);
	if(returnValue == true)
	{
		payload.get("count", count);
	}

	LOG_INFO("AdapterDb", 0, "findKey results = %s ..", payload.getJSONString().c_str());
	return (count > 0) ? true : false;
}

bool AdapterDb::putKind()
{
	LOG_INFO("AdapterDb", 0, "putKind start ..");

	bool returnValue = false;
	LS::Call call;
	LS_PLD::JSONPayload payload;

	pbnjson::JValue indexes1		= pbnjson::Object();
	pbnjson::JValue props1			= pbnjson::Object();
	pbnjson::JValue props1Arr		= pbnjson::Array();

	pbnjson::JValue indexes2		= pbnjson::Object();
	pbnjson::JValue props2			= pbnjson::Object();
	pbnjson::JValue props2Arr		= pbnjson::Array();

	pbnjson::JValue indexesArr		= pbnjson::Array();
	pbnjson::JValue sendObj 		= pbnjson::Object();

	// build indexes json object
	indexes1.put("name", "keyid_index");
	props1.put("name", "keyid");
	props1Arr.append(props1);
	indexes1.put("props", props1Arr);

	indexesArr.append(indexes1);

	// build indexes json object
	indexes2.put("name", "id_perm");
	props2.put("name", "keyid");
	props2.put("name", "permanent");
	props2Arr.append(props2);
	indexes2.put("props", props2Arr);

	indexesArr.append(indexes1);
	indexesArr.append(indexes2);

	// build sendObj json object
	sendObj.put("id", CM_DB8_KIND);
	sendObj.put("owner", CM_DB8_OWNER);
	sendObj.put("indexes", indexesArr);

	// 1. call
	call = handle_.callOneReply(
		"luna://com.palm.db/putKind",
		sendObj.stringify().c_str());

	// 2. wait until timeout
	if(!checkLSMessageReply(call, payload, LS_CALL_WAIT_TIMEOUT_DB8))
	{
		return false;
	}

	payload.get("returnValue", returnValue);
	
	return returnValue;
}

bool AdapterDb::put(const std::string &keyId)
{
	LOG_INFO("AdapterDb", 0, "put start ..");

	bool returnValue = false;
	LS::Call call;
	LS_PLD::JSONPayload payload;

	pbnjson::JValue objects		= pbnjson::Object();
	pbnjson::JValue objectsArr	= pbnjson::Array();
	pbnjson::JValue sendObj 	= pbnjson::Object();

	// build objects json object
	objects.put("_kind", CM_DB8_KIND);
	objects.put("keyid", keyId);
	
	// build sendObj json object
	objectsArr.append(objects);
	sendObj.put("objects", objectsArr);

	// 1. call
	call = handle_.callOneReply(
		"luna://com.palm.db/put",
		sendObj.stringify().c_str());

	// 2. wait until timeout
	if(!checkLSMessageReply(call, payload, LS_CALL_WAIT_TIMEOUT_DB8))
	{
		return false;
	}

	payload.get("returnValue", returnValue);

	LOG_INFO("AdapterDb", 0, "put results = %s ..", payload.getJSONString().c_str());
	
	return returnValue;
}

void AdapterDb::registerServiceStatus()
{
    LOG_INFO("AdapterDb", 0, "registerServiceStatus start ..");

   	mLunaClient.callMultiReply(
		"luna://com.palm.bus/signal/registerServerStatus",
		pbnjson::JObject{{"serviceName", "com.palm.db"}}, this,
		&AdapterDb::registerServiceStatusCb);
}

void AdapterDb::registerServiceStatusCb(LSUtils::LunaResponse &response)
{
    LOG_INFO( "AdapterDb", 0, "registerServiceStatusCb response %s",
              response.getJson().stringify().c_str() );

    bool connected = response.getJson()[ "connected" ].asBool();

    if(connected)
    {
        putKind();
    }
}

AdapterDb::~AdapterDb()
{
    mStatusSubscription.cancel();
    if(_instance != nullptr)
    {
        _instance = nullptr;
    }
}
