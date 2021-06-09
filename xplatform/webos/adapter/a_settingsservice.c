
#include "a_settingsservice.h"
#include "lunaservice2.h"


static LSMessageToken _gLSCall_Token_getSettingsservice = 0;

static BOOLEAN gSetSettingservice = FALSE;


static BOOLEAN _adapter_settingservice_callbackRegister(LSHandle *sh, const char *pServiceName, bool bConnected, void *ctx);
static BOOLEAN _adapter_settingservice_callbackgetSettingsservice(LSHandle *sh, LSMessage *message, void *ctx);
static BOOLEAN _adapter_settingservice_callbacksetSettingsservice(LSHandle *sh, LSMessage *message, void *ctx);

BOOLEAN adapter_settingservice_getSettingsservice(void);
BOOLEAN adapter_settingservice_cancelgetSettingsservice(void);


BOOLEAN adapter_settingservice_getLoadedInfo(void)
{
	return gSetSettingservice;
}


BOOLEAN adapter_settingservice_register(void)
{
	LSError lserror;
	BOOLEAN retValue;

	LSErrorInit(&lserror);

	retValue = LSRegisterServerStatusEx(sample_lunaservice2_getMainHandle(),
								"com.lge.settingsservice",
								(void *)_adapter_settingservice_callbackRegister,
								NULL, NULL, &lserror);

	if (!retValue)
	{
		LSErrorPrint(&lserror, stderr);
		LSErrorFree(&lserror);
	}

	return retValue;
}

static BOOLEAN _adapter_settingservice_callbackRegister(LSHandle *sh, const char *pServiceName, bool bConnected, void *ctx)
{
	BOOLEAN ls_ret = FALSE;

	if (bConnected)
	{
		ls_ret =adapter_settingservice_getSettingsservice();
	}
	else
	{
		ls_ret =adapter_settingservice_cancelgetSettingsservice();
	}

	return ls_ret;
}

BOOLEAN adapter_settingservice_getSettingsservice(void)
{
	LSError lserror;
	BOOLEAN ls_ret;

	LSErrorInit(&lserror);

    ls_ret = LSCall(sample_lunaservice2_getMainHandle(),
                    "luna://com.lge.settingsservice/getSystemSettings",
                    "{\"keys\":[\"setId\"], \"category\":\"option\", \"subscribe\":true}",
                    (void *)_adapter_settingservice_callbackgetSettingsservice,
                    NULL, _gLSCall_Token_getSettingsservice, &lserror);

	if (!ls_ret && LSErrorIsSet(&lserror))
	{
		LSErrorPrint(&lserror, stderr);
		LSErrorFree(&lserror);
	}

	return ls_ret;
}

static BOOLEAN _adapter_settingservice_callbackgetSettingsservice(LSHandle *sh, LSMessage *message, void *ctx)
{
    struct json_object *jobj     = NULL;
    struct json_object *subjobj  = NULL;
    struct json_object *subjobj2 = NULL;
    struct json_object *subjobj3 = NULL;

    const char         *payload;
    BOOLEAN             returnValue = TRUE;
	BOOLEAN				isReset		= FALSE;

    LSMessageRef(message);

    payload = LSMessageGetPayload(message);
    jobj    = json_tokener_parse(payload);

    if (JSON_ERROR(jobj))
    {
        g_critical("\n[ %s(%d) ] json object error !\n", __FUNCTION__, __LINE__);
        LSMessageUnref(message);
        return FALSE;
    }
	
	PMLOG_INFO("LS2 CALLBACK", "%s: received sampleRun", __FUNCTION__);

    if (json_object_object_get_ex(jobj, "settings", &subjobj))
    {
        if (json_object_object_get_ex(subjobj, "", &subjobj2))
        {

            // add here ::  interface api
        }
		gSetSettingservice = TRUE;
    }

    JSON_PUT(jobj);
    LSMessageUnref(message);

    return returnValue;
}


BOOLEAN adapter_settingservice_cancelgetSettingsservice(void)
{
	LSError lserror;
	BOOLEAN ls_ret;

	LSErrorInit(&lserror);

	ls_ret =LSCallCancel( sample_lunaservice2_getMainHandle(),
					_gLSCall_Token_getSettingsservice, &lserror);


	if (!ls_ret && LSErrorIsSet(&lserror))
	{
		LSErrorPrint(&lserror, stderr);
		LSErrorFree(&lserror);
	}

	return ls_ret;
}

BOOLEAN adapter_settingservice_setSettingsservice(char *category, char *key, char *value)
{
	LSError lserror;
	BOOLEAN ls_ret;

	LSErrorInit(&lserror);

	char param[1024];

	if(category == NULL)
		sprintf(param,"{\"category\":\"commercial\", \"settings\":{\"%s\":\"%s\"}}",key,value);
	else
		sprintf(param,"{\"category\":\"%s\", \"settings\":{\"%s\":\"%s\"}}",category,key,value);

	ls_ret = LSCallOneReply(sample_lunaservice2_getMainHandle(),
	                "luna://com.lge.settingsservice/setSystemSettings",
	                param,
	                (void *)_adapter_settingservice_callbacksetSettingsservice,
	                NULL, NULL, &lserror);

	if (!ls_ret && LSErrorIsSet(&lserror))
	{
		LSErrorPrint(&lserror, stderr);
		LSErrorFree(&lserror);
	}

	return ls_ret;
}

BOOLEAN adapter_settingservice_setSettingsserviceBoolean(char *category, char *key, BOOLEAN value)
{
	LSError lserror;
	BOOLEAN ls_ret;

	LSErrorInit(&lserror);

	char param[1024];

	if(category == NULL)
		sprintf(param,"{\"category\":\"commercial\", \"settings\":{\"%s\":%s}}",key,value?"true":"false");
	else
		sprintf(param,"{\"category\":\"%s\", \"settings\":{\"%s\":%s}}",category,key,value?"true":"false");

	ls_ret = LSCallOneReply(sample_lunaservice2_getMainHandle(),
	                "luna://com.lge.settingsservice/setSystemSettings",
	                param,
	                (void *)_adapter_settingservice_callbacksetSettingsservice,
	                NULL, NULL, &lserror);

	if (!ls_ret && LSErrorIsSet(&lserror))
	{
		LSErrorPrint(&lserror, stderr);
		LSErrorFree(&lserror);
	}

	return ls_ret;
}

static BOOLEAN _adapter_settingservice_callbacksetSettingsservice(LSHandle *sh, LSMessage *message, void *ctx)
{
	struct json_object *jobj     = NULL;
	struct json_object *subjobj  = NULL;

	const char         *payload;
	BOOLEAN             returnValue = TRUE;

	LSMessageRef(message);

	payload = LSMessageGetPayload(message);
	jobj    = json_tokener_parse(payload);

	if (JSON_ERROR(jobj))
	{
		g_critical("\n[ %s(%d) ] json object error !\n", __FUNCTION__, __LINE__);
		LSMessageUnref(message);
		return FALSE;
	}

	if (json_object_object_get_ex(jobj, "returnValue", &subjobj))
	{
		returnValue = json_object_get_boolean(subjobj);
	}

	JSON_PUT(jobj);
	LSMessageUnref(message);

	return returnValue;
}

