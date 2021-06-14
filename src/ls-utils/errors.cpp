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

#include <sstream>
#include <string>

#include "errors.h"
#include "logging.h"

std::string string_format_valist(const std::string &fmt_str, va_list ap)
{
    size_t n = fmt_str.size() * 2;
    std::unique_ptr<char[]> formatted(new char[n]);
    va_list apCopy;
    va_copy(apCopy, ap);

    int final_n = vsnprintf(&formatted[0], n, fmt_str.c_str(), ap);
    if (final_n < 0 || final_n >= (int)n) {
        /* There was not enough space, retry */
        /* MS implements < 0 as not large enough */
        n = (size_t)(abs(final_n) + 1);

        formatted.reset(new char[n]);
        vsnprintf(&formatted[0], n, fmt_str.c_str(), apCopy);
    }
    va_end(apCopy);

    return std::string(formatted.get());
}

LunaError::LunaError(int error_code, const char *format, ...)
    : pbnjson::JObject{{"returnValue", false}, {"errorCode", error_code}}
{
    va_list args;
    va_start(args, format);
    this->put("errorMessage", string_format_valist(format, args));
    va_end(args);
};

FatalException::FatalException(const char *file, int line, const std::string msgid, const char *format, ...)
    : std::runtime_error(format), mFile(file), mLine(line)
{
    va_list args;
    va_start(args, format);
    errorMessage = string_format_valist(format, args);
    LOG_ERROR(msgid.c_str(), 0, errorMessage.c_str());
    va_end(args);
};

// FixMe: file and line number not working
const char *FatalException::what()
{
    msg.clear();
    std::ostringstream o;
    o << mFile << ":" << mLine << ": " << errorMessage;
    msg = o.str();
    return msg.c_str();
}