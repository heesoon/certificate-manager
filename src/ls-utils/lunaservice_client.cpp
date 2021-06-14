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

#include "lunaservice_client.h"
#include "logging.h"

using namespace pbnjson;

namespace LSUtils
{

LSUtils::LunaClient::LunaClient(LS::Handle &handle) : mHandle(handle) {}

LSUtils::LunaClient::~LunaClient()
{
    // Cancel all the calls in progress, so we don't get any callbacks on
    // destroyed object.
    for (auto &iter : mCalls) {
        LSCallCancel(mHandle.get(), iter.first, nullptr);
        // Don't care if call cancel errors out.
    }
}

LSMessageToken LSUtils::LunaClient::callOneReply(const std::string &uri, const pbnjson::JValue &params,
                                                 const LSUtils::LunaClient::ResultHandler &handler)
{
    return makeCall(uri, params, true, handler);
}

LSMessageToken LunaClient::callMultiReply(const std::string &uri, const pbnjson::JValue &params,
                                          const LunaClient::ResultHandler &handler)
{
    return makeCall(uri, params, false, handler);
}

LSMessageToken LunaClient::makeCall(const std::string &uri, const pbnjson::JValue &params, bool oneReply,
                                    const LunaClient::ResultHandler &handler)
{
    JValue p = params; // Remove the constness. This is reference counted
                       // object, so no performance penalty.
    LSMessageToken token = 0;
    LS::Error error;

    if (handler) {
        std::unique_ptr<Call> call{new Call(this, 0, handler, oneReply)};

        LSCall(mHandle.get(), uri.c_str(), p.stringify().c_str(), &LunaClient::responseArrived, call.get(), &token,
               error.get());

        if (error.isSet()) {
            throw error;
        }

        call->token = token;
        // Save to be able to clean up on destructor.
        mCalls[token] = std::move(call);
    } else // Fire and forget
    {
        if (!oneReply) {
            throw std::logic_error("Multi reply requires handler method");
        }

        LSCallOneReply(mHandle.get(), uri.c_str(), p.stringify().c_str(), nullptr, nullptr, &token, error.get());

        if (error.isSet()) {
            throw error;
        }
    }

    return token;
}

void LunaClient::cancelCall(LSMessageToken token)
{
    auto iter = mCalls.find(token);

    if (iter == mCalls.end()) {
        // Might be a call with no callback, forward the cancel to luna service.
        LSCallCancel(mHandle.get(), token, nullptr);
    } else {
        cancelCall(iter->second.get());
    }
}

void LunaClient::cancelCall(LunaClient::Call *call)
{
    LSCallCancel(mHandle.get(), call->token, nullptr);
    mCalls.erase(call->token);
}

bool LSUtils::LunaClient::responseArrived(LSHandle *sh, LSMessage *msg, void *ctx)
{
    LS::Message message{msg};
    LunaClient::Call *call = static_cast<LunaClient::Call *>(ctx);
    // call is guaranteed to be valid, see destructor.

    if (sh != call->client->mHandle.get()) {
        // Hmm...
        LOG_ERROR(MSGID_LS2_CALL_RESPONSE_INVALID_HANDLE, 0, "Invalid luna bus handle in response");
        return false;
    }

    // Parse the message.
    JValue payload{}; // Null by default
    bool success;

    if (message.isHubError()) {
        LOG_ERROR(MSGID_LS2_HUB_ERROR, 0, "Hub error during luna call, method: %s, payload: %s", message.getMethod(),
                  message.getPayload());
        success = false;
    } else {
        JValue value = JDomParser::fromString(message.getPayload(), JSchema::AllSchema());

        if (!value.isValid()) {
            LOG_ERROR(MSGID_LS2_RESPONSE_PARSE_FAILED, 0, "Failed to parse luna response to JSON: %s, error: %s",
                      message.getPayload(), value.errorString().c_str());
            success = false;
        } else {
            success = true;
            payload = value;
        }
    }

    LunaResponse response{call, payload, success};

    // Clean up before the handler method. Handler may delete the client and we
    // will not be able to do it afterwards.
    auto handler = call->handler;
    if (call->oneReply) {
        // Invalidates call object!!!
        call->client->cancelCall(call);
    }

    try {
        handler(response);
    } catch (const JsonParseError &e) {
        LOG_ERROR(MSGID_LS2_FAILED_TO_PARSE_PARAMETERS, 0, "Response handler failed to parse response parameters: %s",
                  e.what());
    } catch (std::exception &e) {
        LOG_ERROR(MSGID_UNEXPECTED_EXCEPTION, 0, "Exception thrown while processing luna response handler: %s",
                  e.what());
    } catch (...) {
        LOG_ERROR(MSGID_UNEXPECTED_EXCEPTION, 0, "Exception thrown while processing luna response handler");
    }
    return true;
}

void PersistentSubscription::subscribe(const std::string &uri, const pbnjson::JValue &params,
                                       const ResultHandler &handler)
{
    cancel();

    if (!handler) {
        throw std::logic_error("No response handler set");
    }

    mUri    = uri;
    mParams = params.duplicate(); // Duplicate to avoid caller modifying them
                                  // accidentally. Jvalue is reference counted.
    mResultHandler = handler;

    size_t first_slash  = uri.find("://");
    size_t second_slash = uri.find("/", first_slash + 3);

    if (first_slash == std::string::npos || second_slash == std::string::npos) {
        throw std::runtime_error("PersistentSubscription::subscribe - failed to parse service URI");
    }

    std::string serviceName = uri.substr(first_slash + 3, second_slash - first_slash - 3);
    LOG_ERROR("SERVICENAME", 0, serviceName.c_str());

    mServiceStatusCall = mClient.callMultiReply("luna://com.webos.service.bus/signal/registerServerStatus",
                                                pbnjson::JObject{{"serviceName", serviceName}}, this,
                                                &PersistentSubscription::onServiceStatusResponse);
}

void PersistentSubscription::cancel()
{
    mParams        = pbnjson::JValue();
    mResultHandler = nullptr; // Frees any associated closures.

    mClient.cancelCall(mServiceStatusCall);
    mClient.cancelCall(mSubscriptionCall);
    mServiceStatusCall = LSMESSAGE_TOKEN_INVALID;
    mSubscriptionCall  = LSMESSAGE_TOKEN_INVALID;
}

void PersistentSubscription::onServiceStatusResponse(LunaResponse &response)
{
    bool connected;
    response.param("connected", connected);
    response.finishParseOrThrow(false);

    if (connected && mSubscriptionCall == LSMESSAGE_TOKEN_INVALID) {
        mSubscriptionCall = mClient.callMultiReply(mUri, mParams, mResultHandler);
    } else if (!connected) {
        mClient.cancelCall(mSubscriptionCall);
        mSubscriptionCall = LSMESSAGE_TOKEN_INVALID;
    }
}

} // namespace LSUtils