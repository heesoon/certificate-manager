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

#include "lunasubscription.h"
#include "errors.h"

// Section luna subscription

using namespace LSUtils;
using namespace pbnjson;

LunaSubscription::~LunaSubscription()
{
    if (mServiceHandle) {
        LSCallCancelNotificationRemove(mServiceHandle->get(), subscriberCancelCB, this, nullptr);
    }
}

void LunaSubscription::addSubscription(LunaRequest &request)
{
    if (!request.mSubscribed) {
        LOG_ERROR(MSGID_LS2_NOT_SUBSCRIBED, 0, "Adding subscription, but not a subscribe call.");
        return;
    }

    if (!mServiceHandle) {
        mServiceHandle = request.mService->getHandle();
        LSCallCancelNotificationAdd(mServiceHandle->get(), subscriberCancelCB, this, nullptr);
    } else if (mServiceHandle != request.mService->getHandle()) {
        LOG_ERROR(MSGID_LS2_SUBSCRIBE_FAILED, 0, "Using single subscription point with multiple services not "
                                                 "supported");
        throw std::runtime_error("Using single subscription point with "
                                 "multiple services not supported");
    }

    std::unique_ptr<Item> item{new Item()};
    Item *itemPtr = item.get();
    item->message = request.mMessage;

    //    LOG_INFO("keyword-addSubscription", 0, "%s, token(%s)",
    //             request.getJson().stringify().c_str(), item->message.getUniqueToken());

    // Listen to client disconnect
    // Tricky code here - passing raw pointer to closure.
    // The closure lifetime is the same as pointer lifetime, so we are safe.
    item->disconnectNotifier.set(request, [this, itemPtr] { this->removeSubscription(itemPtr, nullptr); });

    mSubscriptions.emplace_back(std::move(item));
}

void LunaSubscription::sendResponse(const pbnjson::JValue &response, bool forced)
{
    if (!response.isObject()) {
        LOG_ERROR(MSGID_LS2_INVALID_SUBSCRIPTION_RESPONSE, 0, "Response is not a JSON object");
        return;
    }

    const_cast<JValue &>(response).put("returnValue", true);
    std::string payload = const_cast<pbnjson::JValue &>(response).stringify();

    // same data is not transfered in same session
    // For changing mode or input, this is fixed
    if (!forced && (payload == this->mPrevResponse)) {
        return;
    }
    //    LOG_INFO("keyword-sendResponse", 0, "%s, mSubscriptions size(%d)",
    //             payload.c_str(), mSubscriptions.size());

    for (auto &item : mSubscriptions) {
        // TODO (1)
        // not support message.respond(pbnjson::JValu&)
        // item->message.respond(response);
        // so replace to const char*
        item->message.respond(payload.c_str());
        //       LOG_INFO("keyword-sendResponse", 0, "%s",
        //                payload.c_str());
    }

    mPrevResponse = payload;
}

bool LunaSubscription::subscriberCancelCB(LSHandle *sh, const char *uniqueToken, void *context)
{
    LunaSubscription *self = static_cast<LunaSubscription *>(context);
    self->removeSubscription(nullptr, uniqueToken);
    return true;
}

void LunaSubscription::removeSubscription(Item *item, const char *uniqueToken)
{
    bool erased = false;

    for (auto iter = mSubscriptions.begin(); iter != mSubscriptions.end(); iter++) {
        if (iter->get() == item || (uniqueToken && !strcmp(iter->get()->message.getUniqueToken(), uniqueToken))) {
            mSubscriptions.erase(iter);
            erased = true;
            //            LOG_INFO("keyword-removeSubscription", 0, "%s",
            //                     uniqueToken);
            break;
        }
    }

    if (erased && !hasSubscribers() && mCancelHandler) {
        mCancelHandler();
    }
}
