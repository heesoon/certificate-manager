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
 * @file lunaservice_utils.c
 *
 * @brief Convenience functions for sending luna error messages
 *
 */

#include "lunaservice_utils.h"
#include "errors.h"
#include "logging.h"
#include <luna-service2/lunaservice.hpp>
#include <pbnjson/cxx/JValue.h>

using namespace pbnjson;

namespace LSUtils
{

LunaService::LunaService(const std::string &_servicePath, GMainLoop *mainLoop)
    : mServicePath(_servicePath), mHandle(_servicePath.c_str()), mEventLoop(mainLoop)
{
    mHandle.setDisconnectHandler(LunaService::onLunaDisconnect, this);
    mHandle.attachToLoop(mainLoop);
}

LunaService::~LunaService()
{
    // Nothing here
}

void LunaService::registerMethod(const std::string &category, const std::string &methodName, LunaCallHandler handler, const pbnjson::JSchema &schema)
{
    std::string categoryMethod = category + "/" + methodName;

    // Check for duplicate registration
    for (auto &method : mCategoryMethods) {
        if (method->categoryMethod == categoryMethod) {
            std::stringstream error;
            error << "Duplicate registration of method " << categoryMethod;
            throw std::logic_error(error.str());
        }
    }

    std::unique_ptr<MethodInfo> method{new MethodInfo(this, handler, schema, categoryMethod)};

    LSMethod methods[2];
    methods[0] = {methodName.c_str(), &LunaService::methodHandler, LUNA_METHOD_FLAGS_NONE};
    methods[1] = {nullptr, nullptr, LUNA_METHOD_FLAGS_NONE};

    mHandle.registerCategoryAppend(category.c_str(), methods, nullptr);

    // Might be an issue if called from other thread than main loop, see API
    // doc.
    // TODO (1) :: not used yet in drd4tv: not support(2017.04.12)
    // mHandle.setMethodData(category.c_str(), methodName.c_str(),
    // method.get());
    mHandle.setCategoryData(category.c_str(), this);
    mMethodsMap[category + methodName] = method.get();
    // TODO (1)

    mCategoryMethods.emplace_back(std::move(method));
}

bool LunaService::methodHandler(LSHandle *, LSMessage *msg, void *method_context)
{
    LS::Message message{msg};

    // TODO (1) :: not used yet in drd4tv: not support(2017.04.12)
    // MethodInfo* method = static_cast<MethodInfo*>(method_context);
    auto service = reinterpret_cast<LunaService *>(method_context);
    std::string key(message.getCategory());
    key += message.getMethod();
    auto it     = service->mMethodsMap.find(key);
    auto method = it->second; // not error handling
    // TODO (1)

    try {
        if (!method) {
            // Should never happen
            LOG_ERROR(MSGID_LS2_NO_HANDLER, 0, "No handler for method %s %s", message.getCategory(),
                      message.getMethod());
            throw API_ERROR_UNKNOWN;
        }

        const char *payload = message.getPayload();
        JValue value        = JDomParser::fromString(payload, method->schema);

        if (!value.isValid()) {
            LOG_ERROR(MSGID_LS2_CALL_PARSE_FAILED, 0, "Failed to validate luna request against schema: %s, error: %s",
                      payload, value.errorString().c_str());

            if (!JDomParser::fromString(payload, JSchema::AllSchema()).isValid()) {
                throw API_ERROR_MALFORMED_JSON;
            } else {
                throw API_ERROR_SCHEMA_VALIDATION("Failed to validate luna request against schema");
            }
        }

        std::shared_ptr<LunaRequest> request(new LunaRequest{method->service, message, value});
        request->mWeakPtr   = request;
        request->mResponded = true; // For the exception cases

        /*call real method*/
        JValue result = method->handler(*request.get());

        if (!request->mDeferred) {
            request->respond(result);
        } else {
            request->mResponded = false;
        }

        return true;
    } catch (JsonParseError &e) {
        message.respond(API_ERROR_SCHEMA_VALIDATION(e.what()).stringify().c_str());
        return true;
    } catch (LunaError &e) {
        message.respond(e.stringify().c_str());
        return true;
    } catch (const std::exception &e) {
        LOG_ERROR(MSGID_UNEXPECTED_EXCEPTION, 0, "Method '%s' handler throws exception: %s",
                  method ? method->categoryMethod.c_str() : "unknown", e.what());
        return false;
    } catch (...) {
        LOG_ERROR(MSGID_UNEXPECTED_EXCEPTION, 0, "Method '%s' handler throws exception",
                  method ? method->categoryMethod.c_str() : "unknown");
        return false;
    }
}

void LunaService::onLunaDisconnect(LSHandle *, void *data)
{
    auto service = reinterpret_cast<LunaService *>(data);

    LOG_ERROR(MSGID_LS2_DISCONNECTED, 0, "Luna service disconnected.");
    service->mHandle.detach(); // Detaching from mainloop should cause it to
                               // stop, terminating the application.
}

// Section: luna request

LunaRequest::LunaRequest(LunaService *service, LS::Message &message, pbnjson::JValue params)
    : JsonParser(params, true), mService(service), mMessage(message), mDeferred(false), mResponded(false)
{
    JValue subscribeVal = getJson()["subscribe"];
    this->mSubscribed   = (subscribeVal.isValid() && subscribeVal.isBoolean());
}

LunaRequest::~LunaRequest()
{
    if (!mResponded) // Most likely defer call not responded
    {
        mMessage.respond(API_ERROR_NO_RESPONSE);
    }
}

std::function<void(pbnjson::JValue response)> LunaRequest::defer()
{
    if (mDeferred) {
        LOG_ERROR(MSGID_LS2_DOUBLE_DEFER, 0, "Trying to defer a function that's already deferred");
    }

    mDeferred                            = true;
    std::shared_ptr<LunaRequest> request = mWeakPtr.lock();

    // Include a shared_ptr to the request in the capture.
    // This will ensure that LunaRequest is alive as long as there is a copy of
    // this lambda. And will free memory once all copies have been destroyed.
    // Similar to how LS::Message internally works

    return [request](const pbnjson::JValue &response) {
        request->respond(response);
        // Captured shared ptr release will delete the request object.
    };
}

void LunaRequest::respond(const pbnjson::JValue &response)
{
    // Get away from const, this is reference counted pointer, no copying.
    JValue result = response;

    if (!result.isObject()) {
        if (result.isBoolean() && result.asBool()) {
            // This is just a "return true", converted to JValue.
            // Replace by basic "returnValue":true.
            result = JObject{{"returnValue", true}};
        } else {
            result = API_ERROR_INVALID_RESPONSE;
        }
    }

    mMessage.respond(result.stringify().c_str());
    mResponded = true;
}

// Client disconnect handler.

ClientDisconnectNotifier::ClientDisconnectNotifier() : mHandler(nullptr), mService(nullptr), mToken(0) {}

ClientDisconnectNotifier::~ClientDisconnectNotifier()
{
    if (mToken) {
        LSCallCancel(mService->getHandle()->get(), mToken, nullptr);
        mToken = 0;
    }
}

void ClientDisconnectNotifier::set(LunaService *service, const std::string &clientId,
                                   const ClientDisconnectNotifier::Handler &handler)
{
    if (mToken) {
        LSCallCancel(mService->getHandle()->get(), mToken, nullptr);
        mToken = 0;
    }

    if (!service) {
        throw std::runtime_error("service is null");
    }

    // Listen to client down message
    LS::Error error;
    auto payload = pbnjson::JObject{{"serviceName", clientId}};
    bool retVal  = LSCall(service->getHandle()->get(), "luna://com.webos.service.bus/signal/registerServerStatus",
                         payload.stringify().c_str(), clientDownCB, this, &mToken, error.get());

    if (!retVal) {
        LOG_ERROR(MSGID_LS2_REGISTERSERVERSTATUS_FAILED, 0, "Failed to call registerServerStatus");
        throw API_ERROR_UNKNOWN;
    }

    mHandler = handler;
    mService = service;
}

bool ClientDisconnectNotifier::clientDownCB(LSHandle *sh, LSMessage *message, void *context)
{
    JsonParser parser{LSMessageGetPayload(message)};
    bool connected = false;
    parser.param("connected", connected);

    if (!parser.finishParse(false)) {
        LOG_ERROR(MSGID_LS2_REGISTERSERVERSTATUS_FAILED, 0, "Failed to parse registerServerStatus response: %s",
                  LSMessageGetPayload(message));
    }

    if (!connected) {
        // Not connected, notify listener
        ClientDisconnectNotifier *self = static_cast<ClientDisconnectNotifier *>(context);
        LSCallCancel(sh, self->mToken, nullptr);
        self->mToken = 0;

        // Handler method will quite probably destroy us, do everything before
        // calling it.
        if (self->mHandler) {
            self->mHandler();
        }
    }

    return true;
}

} // Namespace LSUtils
