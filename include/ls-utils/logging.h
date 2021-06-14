/*
Copyright (c) 2019 LG Electronics Inc.

This program or software including the accompanying associated documentation
("Software") is the proprietary software of LG Electronics Inc. and or its
licensors, and may only be used, duplicated, modified or distributed pursuant
to the terms and conditions of a separate written license agreement between you
and LG Electronics Inc. ("Authorized License"). Except as set forth in an
Authorized License, LG Electronics Inc. grants no license (express or implied),
rights to use, or waiver of any kind with respect to the Software, and LG
Electronics Inc. expressly reserves all rights in and to the Software and all
intellectual property therein. If you have no Authorized License, then you have
no rights to use the Software in any ways, and should immediately notify LG
Electronics Inc. and discontinue all use of the Software.
*/

#ifndef LOGGING_H
#define LOGGING_H

#include <PmLogLib.h>

extern PmLogContext getPmLogContext();

#define LOG_CRITICAL(msgid, kvcount, ...) PmLogCritical(getPmgetPmLogContext()(), msgid, kvcount, ##__VA_ARGS__)

#define LOG_ERROR(msgid, kvcount, ...) PmLogError(getPmLogContext(), msgid, kvcount, ##__VA_ARGS__)

#define LOG_WARNING(msgid, kvcount, ...) PmLogWarning(getPmLogContext(), msgid, kvcount, ##__VA_ARGS__)

#define LOG_INFO(msgid, kvcount, ...) PmLogInfo(getPmLogContext(), msgid, kvcount, ##__VA_ARGS__)

#define LOG_DEBUG(fmt, ...) PmLogDebug(getPmLogContext(), "%s:%s() " fmt, __FILE__, __FUNCTION__, ##__VA_ARGS__)

#define LOG_TRACE(fmt, ...)                                                                                            \
    PmLogInfo(getPmLogContext(), "TRACE", 0, "%s:%d " fmt, __PRETTY_FUNCTION__, __LINE__, ##__VA_ARGS__)

#define LOG_ESCAPED_ERRMSG(msgid, errmsg)                                                                              \
    do {                                                                                                               \
        gchar *escaped_errtext = g_strescape(errmsg, NULL);                                                            \
        LOG_ERROR(msgid, 1, PMLOGKS("Error", escaped_errtext), "");                                                    \
        g_free(escaped_errtext);                                                                                       \
    } while (0)

#define MSGID_MAINAPP "CertificateManager"

#define MSGID_TRACE "SEBRO_TRACE"

#define MSGID_LUNA_SEND_FAILED "LUNA_SEND_FAILED"
#define MSGID_LUNA_CREATE_JSON_FAILED "LUNA_CREATE_JSON_FAILED"
#define MSGID_UNEXPECTED_EXCEPTION "UNEXPECTED_EXCEPTION"
#define MSGID_LS2_DISCONNECTED "LS2_DISCONNECTED"
#define MSGID_LS2_NO_HANDLER "LS2_NO_HANDLER"
#define MSGID_LS2_NOT_SUBSCRIBED "LS2_NOT_SUBSCRIBED"
#define MSGID_LS2_SUBSCRIBE_FAILED "LS2_SUBSCRIBE_FAILED"
#define MSGID_LS2_CALL_PARSE_FAILED "LS2_CALL_PARSE_FAILED"
#define MSGID_LS2_INVALID_SUBSCRIPTION_RESPONSE "LS2_INVALID_SUBSCRIPTION_RESPONSE"
#define MSGID_LS2_INVALID_RESPONSE "LS2_INVALID_RESPONSE"
#define MSGID_LS2_DOUBLE_DEFER "LS2_DOUBLE_DEFER"
#define MSGID_LS2_CALL_RESPONSE_INVALID_HANDLE "LS2_CALL_RESPONSE_INVALID_HANDLE"
#define MSGID_LS2_HUB_ERROR "LS2_HUB_ERROR"
#define MSGID_LS2_RESPONSE_PARSE_FAILED "LS2_RESPONSE_PARSE_FAILED"
#define MSGID_LS2_FAILED_TO_PARSE_PARAMETERS "LS2_FAILED_TO_PARSE_PARAMETERS"
#define MSGID_LS2_REGISTERSERVERSTATUS_FAILED "LS2_REGISTERSERVERSTATUS_FAILED"

#define MSGID_MALFORMED_JSON "MALFORMED_JSON"
#define MSGID_GET_SYSTEM_SETTINGS_ERROR "GET_SYSTEM_SETTINGS_ERROR"
#define MSGID_SCHEMA_VALIDATION "SCHEMA_VALIDATION"
#define MSGID_MULTIPLE_LUNA_REPLIES "MULTIPLE_LUNA_REPLIES"
#define MSGID_JSON_PARSE_ERROR "JSON_PARSE_ERROR"

#define MSGID_SIGNAL_HANDLER_ERROR "SIGNAL_HANDLER_ERROR"
#define MSGID_TERMINATING "TERMINATING"

#endif // LOGGING_H
