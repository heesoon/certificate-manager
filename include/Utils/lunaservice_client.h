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

#include "lunaservice_utils.h"
#include <unordered_map>
#include <unordered_set>

namespace LSUtils
{
class LunaClient;
class LunaResponse;

/**
 * Luna client object. Manages lifetime of multiple luna calls.
 * Tracks ongoing calls and cancels them if client is destroyed.
 * There can be multiple clients per luna handle.
 * Typical usage is to have a single client for each object with handler
 methods.
 * That way all pending calls and subscriptions will be stopped on object
 destruction.
 * Ensuring no access after free conditions.
 *
 * @example
    class MyClass
    {
    public:
      MyClass(LS::Handle& handle):mLunaClient(handle)
      {
        mLunaClient.callMultiReply(
            "luna://com.webos.service.stuff/getStatus",
            pbnjson::JObject {{"subscribe", true}},
            this, &MyClass::getStatusResponse);
      }
    private:
      void getStatusResponse(LunaResponse& response)
      {
        std::string status;
        std::string payload;
        response.param("status",status);
        response.param("payload",payload).optional();
        response.finishParseOrThrow();

        if (status == "ping")
        {
            mLunaClient.callOneReply(
            "luna://com.webos.service.stuff/pong",
            pbnjson::JObject {{"payload", payload}},
            nullptr);
        }
      }

      LunaClient mLunaClient;
    };
 *
 *
 * //TODO: add subscribe to signal
 */
class LunaClient
{
public:
    /**
     * Handler function signature.
     * @param response response object. Check response.isSuccess if the call
     * succeeded.
     */
    typedef std::function<void(LunaResponse &response)> ResultHandler;

    explicit LunaClient(LS::Handle &handle);
    explicit LunaClient(LunaService &service) : LunaClient(*service.getHandle()){};
    ~LunaClient();

    /**
     * Not copyable.
     */
    LunaClient(const LunaClient &) = delete;
    LunaClient &operator=(const LunaClient &) = delete;

    /**
     * Make a one reply call.
     * If this call succeeds (does not throw) the handler method is guaranteed
     * to be eventually called. Regardless of any error condition within the
     * luna bus. You can use response.isSuccess to check if the response is a
     * success or not, response.finishParse does this internally.
     * @param uri
     * @param params
     * @param handler - if set the handler method will be called. If not set,
     * nothing will be called.
     * @return luna message token that can be used ot cancel the call (even when
     * no callback is set).
     * @throw LS::Error on luna error
     */
    LSMessageToken callOneReply(const std::string &uri, const pbnjson::JValue &params,
                                const LunaClient::ResultHandler &handler);

    /**
     * Make a multi reply call. The call is active until cancelCall or client is
     * deleted. If this call succeeds (does not throw) the handler method is
     * guaranteed to be eventually called at least once. Regardless of any error
     * condition within the luna bus. You can use response.isSuccess to check if
     * the response is a success or not, response.finishParse does this
     * internally.
     * @param uri
     * @param params
     * @param handler - mandatory response handler.
     * @return luna message token, that can be used ot cancel the call.
     * @throw LS::Error on luna error, std::logic_error if no response handler.
     */
    LSMessageToken callMultiReply(const std::string &uri, const pbnjson::JValue &params,
                                  const LunaClient::ResultHandler &handler);

    /**
     * Make a one reply call - convenience method that accepts pointer and
     * member method instead of std::function.
     * @tparam T
     * @param uri
     * @param params
     * @param object
     * @param handler
     * @return
     */
    template <typename T>
    LSMessageToken callOneReply(const std::string &uri, const pbnjson::JValue &params, T *object,
                                void (T::*handler)(LunaResponse &response))
    {
        return callOneReply(uri, params, std::bind(handler, object, std::placeholders::_1));
    }

    /**
     * Make a multi reply call - convenience method that accepts pointer and
     * member method instead of std::function.
     * @tparam T
     * @param uri
     * @param params
     * @param object
     * @param handler
     * @return
     */
    template <typename T>
    LSMessageToken callMultiReply(const std::string &uri, const pbnjson::JValue &params, T *object,
                                  void (T::*handler)(LunaResponse &response))
    {
        return callMultiReply(uri, params, std::bind(handler, object, std::placeholders::_1));
    }

    /**
     * Cancels the call and removes any queued replies.
     * The handler method will not be called after this.
     * @param token
     */
    void cancelCall(LSMessageToken token);

private:
    // Internal call object
    struct Call {
        Call(LunaClient *_client, LSMessageToken _token, const ResultHandler &_handler, bool _oneReply)
            : client(_client), token(_token), handler(_handler), oneReply(_oneReply)
        {
        }

        LunaClient *client;
        LSMessageToken token;
        ResultHandler handler;
        bool oneReply;
    };

    LSMessageToken makeCall(const std::string &uri, const pbnjson::JValue &params, bool oneReply,
                            const LunaClient::ResultHandler &handler);
    void cancelCall(Call *call);

    static bool responseArrived(LSHandle *sh, LSMessage *reply, void *ctx);

    // Instance variables
    LS::Handle &mHandle;

    // Need unique ptr, because we will be passing pointers to Call around.
    std::unordered_map<LSMessageToken, std::unique_ptr<Call>> mCalls;

    friend class LunaResponse;
};

/**
 * Luna response object for luna renspose handler.
 */
class LunaResponse : public JsonParser
{
public:
    /**
     * Cancel the call and do not do any further calls to the handler method.
     */
    inline void cancel() { mShouldCancel = true; }

    /**
     * Check if the response is successful (contains returnValue:true)
     * @return true if successful, false if not.
     */
    inline bool isSuccess() { return mSuccess; }

    /**
     * Calls finishParse and checks if finishParse or the call itself has an
     * error.
     */
    inline bool hasErrors() { return !mSuccess || !JsonParser::finishParse(false); };

private:
    /**
     * Initalize luna request with specified message.
     */
    LunaResponse(LunaClient::Call *call, pbnjson::JValue message, bool isSuccess)
        : JsonParser(message, false), mCall(call), mSuccess(isSuccess), mShouldCancel(false)
    {
    }

    LunaClient::Call *mCall;
    bool mSuccess;
    bool mShouldCancel;

    friend class LunaClient;
};

/**
 * @brief
 * Helper class to manage a persistent subscription.
 * Tracks service online state and performs the call every time the service goes
 * online. The handler method receives all responses, including a failed
 * response if the service is terminated.
 * @example
 *
 * class MyClass{
 *   MyClass(LunaService& service)
 *     : client(service)
 *     , getVolumeSubscription(client)
 *    {
 *
 *     getVolumeSubscription.subscribe("luna://com.webos.audio/getVolume",
 *                                     JObject{{"subscribe", true}},
 *                                     [](LunaResponse& response)
 *        {
 *           int volume;
 *           response.param("volume", volume);
 *           response.finishParseOrThrow(false);
 *
 *           std::cerr << "Volume now is : " << volume << std::endl;
 *        });
 *   }
 *
 *   private:
 *      LunaServiceClient client;
 *
 *      PersistentSubscription getVolumeSubscription;
 * }
 *
 */
class PersistentSubscription
{
public:
    /**
     * Handler function signature.
     * @param response response object. Check response.isSuccess if the call
     * succeeded.
     */
    typedef std::function<void(LunaResponse &response)> ResultHandler;

    PersistentSubscription(LunaClient &client)
        : mClient(client), mServiceStatusCall(LSMESSAGE_TOKEN_INVALID), mSubscriptionCall(LSMESSAGE_TOKEN_INVALID)
    {
    }

    ~PersistentSubscription() { cancel(); }

    /** Non copyable */
    PersistentSubscription(const PersistentSubscription &) = delete;
    PersistentSubscription &operator=(const PersistentSubscription &) = delete;

    /**
     * Start persistent subscription.
     * @param uri URI to subscribe to
     * @param params Json parameters for subscribe call
     * @param handler - mandatory response handler function.
     * @throw LS::Error on luna error, std::logic_error if no response handler.
     */
    void subscribe(const std::string &uri, const pbnjson::JValue &params, const ResultHandler &handler);

    /**
     * Wrapper method that accepts a class method.
     * @param uri URI to subscribe to
     * @param params Json parameters for subscribe call
     * @param object pointer to a class object
     * @param handler pointer to a class method to call
     * @throw LS::Error on luna error, std::logic_error if no response handler.
     */
    template <typename T>
    void subscribe(const std::string &uri, const pbnjson::JValue &params, T *object,
                   void (T::*handler)(LunaResponse &response))
    {
        subscribe(uri, params, std::bind(handler, object, std::placeholders::_1));
    }

    /**
     * Checks if subscription is currently active
     * Note that this will be false immediately after the subscribe call.
     * As the call is async.
     * @return
     */
    inline bool isServiceActive() { return mSubscriptionCall != LSMESSAGE_TOKEN_INVALID; }

    /**
     * Cancel subscription.
     */
    void cancel();

private:
    LunaClient &mClient;
    LSMessageToken mServiceStatusCall;
    LSMessageToken mSubscriptionCall;
    std::string mUri;
    pbnjson::JValue mParams;
    ResultHandler mResultHandler;

    void onServiceStatusResponse(LunaResponse &response);
};

} // Namespace LSUtils