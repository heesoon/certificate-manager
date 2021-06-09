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

#include "jsonutils.h"
#include "logging.h"
#include "lunaservice_utils.h"
#include <luna-service2++/message.hpp>
#include <luna-service2++/subscription.hpp>
#include <sstream>

namespace LSUtils
{

/**
 * Subscription class. For single threaded use only.
 * Use to handle each subscription separately - send per-subscription update.
 * And handle subscription cancels individually.
 * Note this is not thread safe - use within main loop context only.
 */
class LunaSubscription
{
public:
    /**
     * Handler function signature.
     * @param request - request object
     * @return JValue object containing the response.
     * @throw LunaError to return errors. Apropriate error message is sent to
     * caller.
     */
    typedef std::function<void()> CancelHandler;

    /**
     * Create empty subscription object
     */
    LunaSubscription(CancelHandler cancelHandler = nullptr) : mCancelHandler(cancelHandler), mServiceHandle(nullptr){};

    ~LunaSubscription();

    /**
     * Not copyable (maybe will add later).
     */
    LunaSubscription(const LunaSubscription &) = delete;
    LunaSubscription &operator=(const LunaSubscription &) = delete;

    /**
     * Add request to subcription point.
     * @param request request to add
     * @param data user data to associate with the request
     */
    void addSubscription(LunaRequest &request);

    /*
     * Sends reply to existing subscribers and adds a new subscription.
     * Only sends to existing subscribers if it's different than previous one.
     * @param request request to add
     * @param response response to send to other subscribers.
     */
    inline void addSubscriptionAndReply(LunaRequest &request, const pbnjson::JValue &response)
    {
        sendResponse(response);
        addSubscription(request);
    }

    /**
     * Send a new response to all subscribers, if it's different than the
     * previous response.
     * @param response response to send to subscribers.
     */
    void sendResponse(const pbnjson::JValue &response, bool forced = true);

    /**
     * @return true if the subscription has at least one subscriber.
     */
    inline bool hasSubscribers() const { return mSubscriptions.size() > 0; }
    inline size_t getSubscribers() const { return mSubscriptions.size(); }

private:
    struct Item {
        LS::Message message;
        ClientDisconnectNotifier disconnectNotifier;
    };

    void removeSubscription(Item *item, const char *uniqueToken);
    static bool subscriberCancelCB(LSHandle *sh, const char *uniqueToken, void *context);

    std::vector<std::unique_ptr<Item>> mSubscriptions;
    CancelHandler mCancelHandler;
    LS::Handle *mServiceHandle;
    std::string mPrevResponse;
};
}