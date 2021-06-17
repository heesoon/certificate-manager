/* @@@LICENSE
 *
 *      Copyright (c) 2019 LG Electronics Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * LICENSE@@@ */

/**
 * @file lunaservice_utils.h
 *
 * @brief Header file defining convenience functions for parsing luna messages
 * and sending replies.
 *
 */
#pragma once

#include "jsonutils.h"
#include <luna-service2++/message.hpp>
#include <luna-service2++/subscription.hpp>
#include <sstream>
#include <unordered_map>

namespace LSUtils
{

class LunaService;
class LunaRequest;
class ClientDisconnectNotifier;

/**
 * Wrapper class around LS::Handle. Provides convenience methods for method
 * registration. And catches any exceptions thrown during the handler function.
 * //TODO: Add signal support.
 */
class LunaService
{
public:
    /**
     * Handler function signature.
     * @param request - request object
     * @return JValue object containing the response.
     * @throw LunaError to return errors. Apropriate error message is sent to
     * caller.
     */
    typedef std::function<pbnjson::JValue(LunaRequest &request)> LunaCallHandler;

    /**
     * Register new service and attach to the main loop.
     * Use registerMethod to register methods.
     * @param servicePath service name, for example com.webos.service.avoutput
     * @mainLoop GMainLoop instance to use.
     */
    LunaService(const std::string &servicePath, GMainLoop *mainLoop);

    /**
     * Unregisters the service.
     */
    ~LunaService();

    /**
     * Not copyable (because the handle is not copyable).
     */
    LunaService(const LunaService &) = delete;
    LunaService &operator=(const LunaService &) = delete;

    inline LS::Handle *getHandle() { return &this->mHandle; }

    inline GMainLoop *getEventLoop() { return this->mEventLoop; }

    /**
     * Registers a new method on the bus.
     * Helper method that accepts a object pointer and method pointer.
     * @param category category name. For example "/"
     * @param methodName the method name
     * @param handler handler method or lambda to call.
     * @param schema json schema to use. If set, will validate the request
     * against the schema before calling the handler method.
     * @throws std::logic_exception if a method is already registered with
     * specified category and name.
     */
    void registerMethod(const std::string &category, const std::string &methodName, LunaCallHandler handler,
                        const pbnjson::JSchema &schema = pbnjson::JSchema::AllSchema());

    /**
     * Helper method that accepts a object pointer and method pointer.
     * @param category category name. For example "/"
     * @param methodName the method name
     * @param object pointer to the object to call
     * @param handler pointer to object's member method
     * @param schema json schema to use. If set, will validate the request
     * against the schema before calling the handler method.
     * @usage: lunaService.registerMethod("/", "myMethod", this,
     * &MyObj::myMethod);
     * @throws std::logic_exception if a method is already registered with
     * specified category and name.
     */
    template <typename T>
    void registerMethod(const std::string &category, const std::string &methodName, T *object,
                        pbnjson::JValue (T::*handler)(LunaRequest &request),
                        const pbnjson::JSchema &schema = pbnjson::JSchema::AllSchema())
    {
        registerMethod(category, methodName, std::bind(handler, object, std::placeholders::_1), schema);
    };

private:
    class MethodInfo
    {
    public:
        MethodInfo(LunaService *_service, LunaCallHandler &_handler, const pbnjson::JSchema &_schema,
                   const std::string &_categoryMethod)
            : service(_service), handler(_handler), schema(_schema), categoryMethod(_categoryMethod){};

        LunaService *service;
        LunaCallHandler handler;
        pbnjson::JSchema schema;
        std::string categoryMethod;
    };

    static void onLunaDisconnect(LSHandle *sh, void *user_data);

    /*proxy for luna methods*/
    static bool methodHandler(LSHandle *sh, LSMessage *msg, void *method_context);

public:
    const std::string mServicePath;

private:
    LS::Handle mHandle;
    GMainLoop *mEventLoop;
    std::vector<std::unique_ptr<MethodInfo>> mCategoryMethods;

    // TODO (1) :: not used yet in drd4tv: not support(2017.04.12)
    std::unordered_map<std::string, MethodInfo *> mMethodsMap;
};

/**
 * A wrapper class around a luna request.
 * Provides convenience methods for parsing the request to C++ variables
 * and creating a reply.
 * Usage example:
 *
 * pbnjson::JValue MyClass::lunaHanlderMethod(LSUtils::LunaRequest& request)
 * {
 *    std::string contextName;
 *    std::string audioType;
 *    uint8_t portNumber;
 *    std::vector<AVResource> resourceList; // AVResource implements
 * JsonDataObject
 *
 *    request.param("context", contextName);
 *    request.paramArray("resourceList", resourceList);
 *    request.param("audioType", audioType).optional(true);
 *    request.param("portNumber", portNumber).optional(true).defaultValue(255);
 *    request.finishParseOrThrow();
 *
 *
 *    Context& context = getContextOrThrow(); // Throws API_ERROR that is
 * converted to error response.
 *
 *    if (!context.doSomeStuff())
 *    {
 *      return API_ERROR_SOME_STUFF_FAILED;
 *    }
 *
 *    return true;        // Equivalent to return JObject{{"returnValue":true}}
 * }
 */
class LunaRequest : public JsonParser
{
public:
    typedef std::function<void(pbnjson::JValue response)> ResponseFunc;

    /**
     * Initalize luna request with specified message.
     */
    LunaRequest(LunaService *service, LS::Message &message, pbnjson::JValue params);
    ~LunaRequest();

    /** Not copyable. */
    LunaRequest(const LunaRequest &) = delete;
    LunaRequest &operator=(const LunaRequest &) = delete;

    /**
     * Defer the response to this call.
     * Can call this only once per request.
     * Can send responses as long as you have the ResponseFunc.
     * Is automatically cleaned up once all copies of ResponseFunc go out of
     * scope.
     * @return a function object to be called to send response.
     *     One or more responses can be sent.
     *
     * @example
     *     JValue handler(LunaRequest& request)
     *     {
     *        auto responseFunction = request.defer();
     *
     *        // Delay response by 1 second.
     *        setTimeout(1000, [responseFunction]()
     *        {
     *           responseFunction(true);
     *        });
     *
     *        return true; // The return value is ignored if the call is
     * deferred.
     *     }
     */
    ResponseFunc defer();

	/*!
	 * \return sender id.
	 */
	inline std::string getSender()
	{
		if(mMessage.getSender())
			return mMessage.getSender();
		else
			return "UNKNOWN";
	}
	
	inline std::string getSenderServiceName()
	{
		if(mMessage.getSenderServiceName())
			return mMessage.getSenderServiceName();
		else
			return "UNKNOWN";
	}
	
	inline std::string getApplicationID()
	{
		if(mMessage.getApplicationID())
			return mMessage.getApplicationID();
		else
			return "UNKNOWN";
	}
	
	/*!
	 * \return message.
	 */
	inline LS::Message& getMessage()
	{
		return mMessage;
	}

private:
    void respond(const pbnjson::JValue &response);

    LunaService *mService;
    LS::Message mMessage;

    std::weak_ptr<LunaRequest> mWeakPtr; // For use in defer
    bool mDeferred;                      // Response deferred.
    bool mSubscribed;                    // This is a subscription call
    bool mResponded;                     // If at least one response is sent back.

    friend class LunaSubscription;
    friend class LunaService;
    friend class ClientDisconnectNotifier;
};

/**
 * Notifies when a client disconnects.
 */
class ClientDisconnectNotifier
{
public:
    typedef std::function<void()> Handler;

    ClientDisconnectNotifier();
    ~ClientDisconnectNotifier();

    /** Non copyable */
    ClientDisconnectNotifier(const ClientDisconnectNotifier &) = delete;
    ClientDisconnectNotifier &operator=(const ClientDisconnectNotifier &) = delete;

    /**
     * Start monitoring client state.
     * Will call the handler method at most once.
     * Subsequent client reconnects and disconnects are not monitored.
     * If client already disconnected, will schedule a handler call later on.
     *
     * @param request used to determine the client.
     * @param handler handler method to call
     */
    inline void set(const LunaRequest &request, const Handler &handler)
    {
        set(request.mService, request.mMessage.getSender(), handler);
    }

    /**
     * Start monitoring client state.
     * Will call the handler method at most once.
     * Subsequent client reconnects and disconnects are not monitored.
     * If client already disconnected, will schedule a handler call later on.
     *
     * @param service luna service
     * @param clientId client id, use message.getSender();
     * @param handler handler method to call
     */
    void set(LunaService *service, const std::string &clientId, const Handler &handler);

private:
    static bool clientDownCB(LSHandle *sh, LSMessage *message, void *context);

    Handler mHandler;
    LunaService *mService;
    LSMessageToken mToken;
};

} // Namespace LSUtils
