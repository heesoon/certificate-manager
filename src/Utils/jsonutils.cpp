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

#include "jsonutils.h"
#include "errors.h"

using namespace pbnjson;

namespace LSUtils
{

JsonParseError::JsonParseError(const std::string &format, ...)
{
    va_list args;
    va_start(args, format);
    this->message = string_format_valist(format, args);
    va_end(args);
}

JsonParser::JsonParser(pbnjson::JValue json, bool throwExceptionOnError)
    : mJsonValue(json), mThrowOnError(throwExceptionOnError), mNumberOfFields(0)
{
}

JsonParser::JsonParser(const char *payload, bool throwExceptionOnError)
    : mThrowOnError(throwExceptionOnError), mNumberOfFields(0)
{
    mJsonValue = JDomParser::fromString(payload, JSchema::AllSchema());

    if (!mJsonValue.isValid()) {
        LOG_ERROR(MSGID_MALFORMED_JSON, 0, "Failed to parse string to JSON: %s, error: %s", payload,
                  mJsonValue.errorString().c_str());

        if (throwExceptionOnError) {
            throw JsonParseError("Malformed JSON");
        } else {
            mDeferredError.reset(new JsonParseError("Malformed JSON"));
        }
    }
}

void checkConversionResultOrThrow(ConversionResultFlags result)
{
    if (result != CONV_OK) {
        const char *message;

        if (CONV_HAS_OVERFLOW(result)) {
            message = "Integer value out of bounds";
        } else if (CONV_HAS_NOT_A_NUM(result)) {
            message = "Integer value not a number";
        } else if (CONV_HAS_PRECISION_LOSS(result)) {
            message = "Integer requested, but fractional value provided";
        } else {
            message = "parse failed";
        }

        throw JsonParseError(message);
    }
}

/* parseValue specializations*/

template <>
void parseValue<int32_t>(const JValue &value, int32_t &destination)
{
    ConversionResultFlags f;
    if (value.isNumber()) {
        f = value.asNumber(destination);
    } else if (value.isString()) // NumericString
    {
        f = JValue(NumericString(value.asString())).asNumber(destination);
    } else {
        throw JsonParseError("not a number");
    }

    checkConversionResultOrThrow(f);
}

template <>
void parseValue<int64_t>(const JValue &value, int64_t &destination)
{
    if (!value.isNumber()) {
        throw JsonParseError("not a number");
    }

    ConversionResultFlags f = value.asNumber(destination);
    checkConversionResultOrThrow(f);
}

template <>
void parseValue<int8_t>(const JValue &value, int8_t &destination)
{
    int32_t val = 0;
    parseValue(value, val);
    ConversionResultFlags f = 0;
    if (val < -0x80) {
        f |= CONV_NEGATIVE_OVERFLOW;
    } else if (val > 0x7F) {
        f |= CONV_POSITIVE_OVERFLOW;
    }

    checkConversionResultOrThrow(f);
    destination = static_cast<int8_t>(val);
}

template <>
void parseValue<uint8_t>(const JValue &value, uint8_t &destination)
{
    int32_t val = 0;
    parseValue(value, val);
    ConversionResultFlags f = 0;
    if (val < 0) {
        f |= CONV_NEGATIVE_OVERFLOW;
    } else if (val > 0xFF) {
        f |= CONV_POSITIVE_OVERFLOW;
    }

    checkConversionResultOrThrow(f);
    destination = static_cast<uint8_t>(val);
}

template <>
void parseValue<uint16_t>(const JValue &value, uint16_t &destination)
{
    int32_t val = 0;
    parseValue(value, val);

    ConversionResultFlags f = 0;
    if (val < 0) {
        f |= CONV_NEGATIVE_OVERFLOW;
    } else if (val > 0xFFFF) {
        f |= CONV_POSITIVE_OVERFLOW;
    }

    checkConversionResultOrThrow(f);
    destination = static_cast<uint16_t>(val);
}

template <>
void parseValue<double>(const JValue &value, double &destination)
{
    if (!value.isNumber()) {
        throw JsonParseError("not a number");
    }

    ConversionResultFlags f = value.asNumber(destination);
    // Ignore precision loss - may contain more fraction digits than double can
    // hold.
    f &= ~static_cast<int>(CONV_PRECISION_LOSS);
    checkConversionResultOrThrow(f);
}

template <>
void parseValue<bool>(const JValue &value, bool &destination)
{
    if (!value.isBoolean()) {
        throw JsonParseError("not a boolean");
    }

    ConversionResultFlags error = value.asBool(destination);
    checkConversionResultOrThrow(error);
}

template <>
void parseValue<std::string>(const JValue &value, std::string &destination)
{
    if (!value.isString()) {
        throw JsonParseError("not a string");
    }
    ConversionResultFlags f = value.asString(destination);
    checkConversionResultOrThrow(f);
}

template <>
void parseValue<JsonDataObject>(const JValue &value, JsonDataObject &destination)
{
    if (!value.isObject()) {
        throw JsonParseError("not an object");
    }

    ConversionResultFlags error = destination.parseFromJson(value);
    checkConversionResultOrThrow(error);
}

template <>
void parseValue<JValue>(const JValue &value, JValue &destination)
{
    destination = value;
}

void JsonParser::finishParseOrThrow(bool strict)
{
    if (mDeferredError) {
        throw * mDeferredError;
    }

    if (strict && this->mNumberOfFields != mJsonValue.objectSize()) {
        throw JsonParseError("Failed to validate against schema: Unexpected fields");
    }
}

bool JsonParser::finishParse(bool strict)
{
    try {
        finishParseOrThrow(strict);
        return true;
    } catch (const JsonParseError &e) {
        return false;
    }
}

JsonParser JsonParser::getObject(const char *name)
{
    JValue obj;
    param(name, obj);

    if (!obj.isObject()) {
        throw JsonParseError("not an object");
    }

    return JsonParser(obj, mThrowOnError);
}

bool JsonParser::hasKey(const char *name) { return mJsonValue.hasKey(name); }

} // Namespace lsutils
