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

#pragma once

#include <pbnjson.hpp>

std::string string_format_valist(const std::string &fmt_str, va_list ap);

/**
 * Error class to use for sending Luna error response.
 * Throw within a handler method to return early and send error response to
 * caller. Doubles as JValue and can be returned.
 */
class LunaError : public pbnjson::JObject
{
public:
    LunaError(int error_code, const std::string &_message)
        : pbnjson::JObject{{"returnValue", false}, {"errorCode", error_code}, {"errorMessage", _message}} {};

    LunaError(const LunaError &e) : pbnjson::JObject(e) {}

    LunaError(int error_code, const char *format, ...);
};

class FatalException : public std::runtime_error
{
private:
    std::string msg;
    std::string errorMessage;
    const char *mFile;
    int mLine;

public:
    FatalException(const char *file, int line, const std::string msgid, const char *format, ...);

    ~FatalException(){};

    const char *what();
};

#define API_ERROR_UNKNOWN LunaError(1, "Unknown error")
#define API_ERROR_MALFORMED_JSON LunaError(2, "Malformed JSON")
#define API_ERROR_SCHEMA_VALIDATION(...) LunaError(3, __VA_ARGS__)
#define API_ERROR_INVALID_PARAMETERS(...) LunaError(4, __VA_ARGS__)
#define API_ERROR_INVALID_RESPONSE LunaError(5, "Response is not a JSON object")
#define API_ERROR_NO_RESPONSE LunaError(6, "The service did not send a reply").stringify().c_str()

// General service errors
#define API_ERROR_NOT_IMPLEMENTED LunaError(10, "Not implemented")
#define API_ERROR_HAL_ERROR LunaError(20, "Driver error while executing the command")

// Video errors
#define API_ERROR_VIDEO_NOT_CONNECTED LunaError(100, "Video not connected")
#define API_ERROR_DOWNSCALE_LIMIT(...) LunaError(102, __VA_ARGS__)
#define API_ERROR_UPSCALE_LIMIT(...) LunaError(103, __VA_ARGS__)

// Audio errors
#define API_ERROR_AUDIO_NOT_CONNECTED LunaError(200, "Audio not connected")
#define API_ERROR_INVALID_SPKTYPE(name) LunaError(201, "tvSoundOutput %s not implemented", name)
#define API_ERROR_VOLUME_LIMIT(msg) LunaError(202, msg)

#define SOUND_FUNC_EXCEPTION(...) throw FatalException(__FILE__, __LINE__, "SOUND_FUNC_ERROR", __VA_ARGS__)
