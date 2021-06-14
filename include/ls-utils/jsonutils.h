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

#include "logging.h"
#include <exception>
#include <functional>
#include <pbnjson.hpp>
#include <string>
#include <unordered_map>

#define FINISH_PARSE_OR_RETURN_FALSE(parser)                                                                           \
    if (!(parser).finishParse())                                                                                       \
    LOG_WARNING(MSGID_JSON_PARSE_ERROR, 0, "Failed to parse JSON: file %s:%d, %s", __FILE__, __LINE__,                 \
                (parser).getError().c_str())

namespace LSUtils
{

template <typename T>
class JsonParseContext;

/**
 * Base class for parse errors that can be thrown in parseFromJson
 * implementation.
 */
class JsonParseError : public std::exception
{
public:
    JsonParseError(const std::string &format, ...);

    const char *what() const noexcept { return message.c_str(); }

public:
    std::string message;
};

/**
 * Base class for objects that can be parsed from JSON using LunaRequest.
 */
class JsonDataObject
{
public:
    /**
     * Method to parse from JSON.
     * @param value json value to store
     * @return 0 on success, other values on error.
     *   See ConversionResult in jconversion.h for list of possible errors.
     * @throw JsonParseError on error, to send custom error message.
     *   A prefix "Field <fieldName> " will be added to your message.
     */
    virtual ConversionResultFlags parseFromJson(const pbnjson::JValue &value) = 0;
};

/**
 * Helper class to validate JSON against schema and parse to C++ objects.
 * With the aim to provide a clean and concise syntax.
 * @example
 *    std::string contextName;
 *    std::string audioType;
 *    uint8_t portNumber;
 *    std::vector<AVResource> resourceList; // AVResource implements
 * JsonDataObject
 *
 *  JsonParser parser(jvalueObject);
 *    parser.param("context", contextName);
 *    parser.paramArray("resourceList", resourceList);
 *    parser.param("audioType", audioType).optional(true);
 *    parser.param("portNumber", portNumber).optional(true).defaultValue(255);
 *    parser.finishParseOrThrow();
 */
class JsonParser
{
public:
    /**
     * Initalize luna parser with specified json data.
     */
    explicit JsonParser(pbnjson::JValue json, bool throwExceptionOnError = false);

    explicit JsonParser(const char *pyload, bool throwExceptionOnError = false);

    /**
     * Returns the json data.
     */
    pbnjson::JValue getJson() { return this->mJsonValue; }

    /** Look up a json field named *name* and store it's value in the
     * *destination*. This is polymorphic method and the parsing implementation
     * depends on the type of the destination field. The following checks are
     * performed and appropriate error messages are sent:
     * - field does not exist (overrideable with LunaParseContext::optional()
     * - field type does not correspond to the destination type.
     * - integral field value does not fit in destination type (overflow,
     * underflow).
     *
     * @param name field name
     * @param destination reference to variable to store the value in
     * @param mandatory if true, the field is mandatory
     * @param def default value
     * @param valueSet if non-null, will be set to true if non-default value is
     * set or to false if default value is used or parse failed.
     * @return LunaParseContext for adding more constraints using call chaining.
     *         The return value shall not be assigned to a variable. It depends
     * on destructor being called to finalize checks.
     * @throw JsonParseError if parse errors encountered.
     * */
    template <typename T>
    JsonParseContext<T> param(const char *name, T &destination);

    template <typename IT, typename T>
    JsonParseContext<T> paramMap(const char *name, T &destination, const std::unordered_map<IT, T> &valueMap);

    template <typename IT, typename T, size_t N>
    JsonParseContext<T> paramMap(const char *name, T &destination, const std::array<std::pair<IT, T>, N> &valueMap);

    template <typename IT, typename T>
    JsonParseContext<T> paramMap(const char *name, T &destination, std::initializer_list<std::pair<IT, T>> valueMap);

    /**
     * Parse array object to std::vector.
     * Semantics similar to param.
     * The array value type must be .param parseable.
     * @param name field name
     * @param destination reference to array to store the values in
     * @return LunaParseContext for adding more constraints using call chaining.
     *         The return value shall not be assigned to a variable. It depends
     * on destructor being called to finalize checks.
     * @throw JsonParseError if parse errors encountered.
     * */
    template <typename T>
    JsonParseContext<std::vector<T>> paramArray(const char *name, std::vector<T> &destination);

    /**
     * Parse array object to std::vector.
     * Individual items will be parsed using parserFunc.
     *
     * @param name field name
     * @param destination reference to array to store the values in
     * @param parserFunc a function to parse individual items.
     *                   Can throw JsonParseException to indicate parse error.
     * @return LunaParseContext for adding more constraints using call chaining.
     *         The return value shall not be assigned to a variable. It depends
     * on destructor being called to finalize checks.
     * @throw JsonParseError if parse errors encountered.
     */
    template <typename T>
    JsonParseContext<std::vector<T>> paramArray(const char *name, std::vector<T> &destination,
                                                std::function<void(const pbnjson::JValue &, T &)> parserFunc);

    /**
     * Get a JsonParser object for a sub-value.
     *
     * @param name the json key that contains the object.
     * @return JsonParser for the sub-object.
     * @throws JsonParseError if key does not exist or is not an object.
     *
     * @example
     * input: {"video":{"available":true}}

     * bool available;
     * auto video = parser.getObject(video);
     * video.param("available", available);
     * video.finishParseOrThrow();
     *
     */
    JsonParser getObject(const char *name);

    /**
     * Get error string if previous parse failed
     * @return Return error message if parse error or empty string.
     */
    inline std::string getError()
    {
        if (mDeferredError) {
            return mDeferredError->message;
        } else {
            return "";
        }
    }

    /**
     * Indicate that there will be no more fields in the request.
     * Does final checks if parsing is successful.
     *
     * @param strict - of true, considers extra fields in request as an error.
     * @throw JsonParseError if parse errors encountered.
     */
    void finishParseOrThrow(bool strict = false);

    /**
     * Indicate that there will be no more fields in the request.
     * Does final checks if parsing is successful.
     *
     * @param strict - of true, considers extra fields in request as an error.
     */
    bool finishParse(bool strict = false);

    /**
     * Check whether the given key is contained in the json object
     * @param name The json key to look for
     * @return True if the key is present, false otherwise
     */
    bool hasKey(const char *name);

    // Deferred error, will throw on next .param or .finishParse.
    // Public to be accessible from all JsonParseContext template
    // instantiations.
    std::unique_ptr<JsonParseError> mDeferredError;

private:
    pbnjson::JValue mJsonValue;

    bool mThrowOnError;
    ssize_t mNumberOfFields;
};

/**
 * Field parse context. Use to specify additional constraints for the field.
 * @example
 *   int v;
 *   bool vSet;
 *
 *   request.param("intField",
 * v).optional(true).defaultValue(5).min(0).max(10).checkValueSet(vSet);
 */
template <typename T>
class JsonParseContext
{
public:
    JsonParseContext(JsonParser &request, const char *fieldName, T &destination, bool valueSet, bool valueNull)
        : mParser(request), mFieldName(fieldName), mDestination(destination), mValueSet(valueSet),
          mValueNull(valueNull), mOptional(false), mAllowNull(false)
    {
    }

    /// Copy constructor. Acts like a move constructor.
    JsonParseContext(const JsonParseContext<T> &context)
        : mParser(context.mParser), mFieldName(context.mFieldName), mDestination(context.mDestination),
          mValueSet(context.mValueSet), mOptional(context.mOptional), mAllowNull(context.mAllowNull)
    {
        // Set mValueSet to true to prevent destructor operations on the
        // original.
        const_cast<JsonParseContext<T> &>(context).mValueSet = true;
    }

    /** No assignments. */
    void operator=(const JsonParseContext<T> &context) = delete;

    /* Called when .param expression ends. */
    ~JsonParseContext()
    {
        // Cannot throw in destructor, defer the exceptions.
        if (!mValueSet) {
            if (!mOptional && !mParser.mDeferredError) {
                mParser.mDeferredError =
                    std::unique_ptr<JsonParseError>(new JsonParseError("Failed to validate against schema: "
                                                                       "Missing mandatory field: '%s'",
                                                                       mFieldName));
            }

            if (mValueNull && !mAllowNull && !mParser.mDeferredError) {
                mParser.mDeferredError =
                    std::unique_ptr<JsonParseError>(new JsonParseError("Failed to validate against schema: "
                                                                       "Field '%s' cannot be null",
                                                                       mFieldName));
            }
        }
    }

    /**
     * Specify that the parameter is optional. It's mandatory buy default.
     * @param isOptional
     * @param allowNull if true null value is treated as value not set.
     */
    inline JsonParseContext &optional(bool isOptional = true, bool allowNull = false)
    {
        mOptional  = isOptional;
        mAllowNull = allowNull;
        return *this;
    };

    /**
     * Save value set flag into a bool variable.
     * If the destination is set from JValue, sets value to true.
     * If the destination is not set or set from default, sets value to false.
     * @value reference to boolean that will be set.
     */
    inline JsonParseContext &checkValueSet(bool & /*out*/ value)
    {
        value = mValueSet;
        return *this;
    };

    /**
     * Set default value.
     * If destination is not set from JValue, sets it to this value.
     * @value the value to set.
     */
    inline JsonParseContext &defaultValue(const T &value)
    {
        if (!mValueSet) {
            mDestination = value;
        }
        return *this;
    };

    /**
     * Specify minimum value.
     * @param value - minimal value
     * @throw JsonParseErrorr if min value check fails.
     */
    inline JsonParseContext &min(const T &value)
    {
        if (mValueSet && mDestination < value && !mParser.mDeferredError) {
            mParser.mDeferredError =
                std::unique_ptr<JsonParseError>(new JsonParseError("Failed to validate against schema: Field "
                                                                   "'%s' value less than minimum",
                                                                   mFieldName));
        }
        return *this;
    };

    /**
     * Specify maximum value.
     * @param value - maximum value
     * @throw LunaError if min value check fails.
     */
    inline JsonParseContext &max(const T &value)
    {
        if (mValueSet && mDestination > value && !mParser.mDeferredError) {
            mParser.mDeferredError =
                std::unique_ptr<JsonParseError>(new JsonParseError("Failed to validate against schema: Field "
                                                                   "'%s' value greater than than maximum",
                                                                   mFieldName));
        }
        return *this;
    };

    /**
     * Specify a list of allowed values. The check is performed only if the
     * value is read from JValue.
     * @param values - array of values.
     * @throw LunaError value not in allowed list.
     */
    inline JsonParseContext &allowedValues(std::initializer_list<T> values)
    {
        if (mValueSet) {
            for (const auto &value : values) {
                if (value == mDestination) {
                    return *this;
                }
            }

            if (!mParser.mDeferredError) {
                mParser.mDeferredError =
                    std::unique_ptr<JsonParseError>(new JsonParseError("Failed to validate against schema: "
                                                                       "Field '%s' value not valid",
                                                                       mFieldName));
            }
        }
        return *this;
    };

private:
    JsonParser &mParser;
    const char *mFieldName;
    T &mDestination;
    bool mValueSet;
    bool mValueNull;

    bool mOptional;
    bool mAllowNull;

    friend class LunaRequest;
};

/* Template method implementations */

/**
 * Check conversion result and throws appropriate JsonParseException if not OK.
 */
void checkConversionResultOrThrow(ConversionResultFlags result);

/**
 * Template method to do the parsing.
 * A list of specializations for basic data types is provided in
 * lunaservice_utils.cpp
 * @param value - the value to parse
 * @param destination set this value if parsing successful
 * @throw JsonParseException on parse error
 */
template <typename T, typename Enable = void>
void parseValue(const pbnjson::JValue &value, T &destination);

/**
 * Template method to do the parsing. Accepts both basic types and objects
 * derived from JsonDataObject.
 * @param value - the value to parse
 * @param destination set this value if parsing successful
 * @throw JsonParseException on parse error
 */
template <typename T>
void parseValueOrDataObject(const pbnjson::JValue &value, T &destination)
{
    // This is compile time constant, will compile to one or the other
    if (std::is_base_of<JsonDataObject, T>::value) {
        parseValue(value, reinterpret_cast<JsonDataObject &>(destination));
    } else {
        parseValue(value, destination);
    }
}

template <typename T>
JsonParseContext<T> JsonParser::param(const char *name, T &destination)
{
    try {
        if (mDeferredError) {
            auto err = std::move(mDeferredError);
            throw * err;
        }

        if (name == nullptr) {
            throw JsonParseError("Internal error while parsing message, field name is null");
        }

        bool hasKey = mJsonValue.hasKey(name);
        bool isNull = hasKey && mJsonValue[name].isNull();

        if (hasKey) {
            mNumberOfFields++;
        }

        if (hasKey && !isNull) {
            parseValueOrDataObject(mJsonValue[name], destination);
            return JsonParseContext<T>(*this, name, destination, true, false);
        } else {
            return JsonParseContext<T>(*this, name, destination, false, isNull);
        }
    } catch (const JsonParseError &e) {
        if (mThrowOnError) {
            throw e;
        } else {
            mDeferredError = std::unique_ptr<JsonParseError>(new JsonParseError(e));
            return JsonParseContext<T>(*this, "", destination, false, false);
        }
    }
}

template <typename IT, typename T>
JsonParseContext<T> JsonParser::paramMap(const char *name, T &destination, const std::unordered_map<IT, T> &valueMap)
{
    IT intermediateValue;
    bool valueSet;
    bool found = false;
    param(name, intermediateValue).optional().checkValueSet(valueSet);
    if (valueSet) {
        const auto iter = valueMap.find(intermediateValue);
        if (iter != valueMap.cend()) {
            found       = true;
            destination = iter->second;
        } else if (!mDeferredError) {
            mDeferredError = std::unique_ptr<JsonParseError>(
                new JsonParseError("Failed to validate against schema: Field '%s' value not valid", name));
        }
    }

    return JsonParseContext<T>(*this, name, destination, valueSet && found, false);
}

template <typename IT, typename T, size_t N>
JsonParseContext<T> JsonParser::paramMap(const char *name, T &destination,
                                         const std::array<std::pair<IT, T>, N> &valueMap)
{
    IT intermediateValue;
    bool valueSet;
    bool found = false;
    param(name, intermediateValue).optional().checkValueSet(valueSet);

    if (valueSet) {
        for (size_t i = 0; i < N; i++) {
            if (valueMap[i].first == intermediateValue) {
                found       = true;
                destination = valueMap[i].second;
                break;
            }
        }

        if (!found && !mDeferredError) {
            mDeferredError = std::unique_ptr<JsonParseError>(
                new JsonParseError("Failed to validate against schema: Field '%s' value not valid", name));
        }
    }

    return JsonParseContext<T>(*this, name, destination, valueSet && found, false);
}

template <typename IT, typename T>
JsonParseContext<T> JsonParser::paramMap(const char *name, T &destination,
                                         std::initializer_list<std::pair<IT, T>> valueMap)
{
    IT intermediateValue;
    bool valueSet;
    bool found = false;
    param(name, intermediateValue).optional().checkValueSet(valueSet);

    if (valueSet) {
        for (auto iter = std::begin(valueMap); iter != std::end(valueMap); ++iter) {
            if (iter->first == intermediateValue) {
                found       = true;
                destination = iter->second;
                break;
            }
        }

        if (!found && !mDeferredError) {
            mDeferredError = std::unique_ptr<JsonParseError>(
                new JsonParseError("Failed to validate against schema: Field '%s' value not valid", name));
        }
    }

    return JsonParseContext<T>(*this, name, destination, valueSet && found, false);
}

template <typename T>
JsonParseContext<std::vector<T>> JsonParser::paramArray(const char *name, std::vector<T> &destination)
{
    std::function<void(const pbnjson::JValue &, T &)> parserFunc = &parseValueOrDataObject<T>;
    return paramArray(name, destination, parserFunc);
}

template <typename T>
JsonParseContext<std::vector<T>> JsonParser::paramArray(const char *name, std::vector<T> &destination,
                                                        std::function<void(const pbnjson::JValue &, T &)> parserFunc)
{
    bool valueSet = false;
    bool isNull   = false;

    try {
        if (mDeferredError) {
            auto err = std::move(mDeferredError);
            throw * err;
        }

        pbnjson::JValue array;
        param(name, array).optional().checkValueSet(valueSet);

        if (valueSet) {
            isNull = array.isNull();

            if (!isNull) {
                if (!array.isArray()) {
                    throw JsonParseError("not an array");
                }

                destination.clear();
                destination.reserve((uint32_t)array.arraySize());

                for (ssize_t i = 0; i < array.arraySize(); i++) {
                    pbnjson::JValue value = array[i];
                    destination.emplace_back();
                    T &item = destination[destination.size() - 1];

                    try {
                        parserFunc(value, item);
                    } catch (const JsonParseError &parseError) {
                        throw JsonParseError("Failed to validate against schema: Field '%s': %s", name,
                                             parseError.message.c_str());
                    }
                }
            }
        }
    } catch (const JsonParseError &e) {
        if (mThrowOnError) {
            throw e;
        } else {
            mDeferredError = std::unique_ptr<JsonParseError>(new JsonParseError(e));
        }
    }

    return JsonParseContext<std::vector<T>>(*this, name, destination, valueSet, isNull);
}

} // Namespace LSUtils
