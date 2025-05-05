#pragma once
#include <Logger.h>
#include "WebSocketClient.hpp"
#include "BlockedPacketException.hpp"
#include <json/json.h>

class FirewallLogger
{
public:

    static FirewallLogger& getInstance();

    void error(const std::string& msg);
    void info(const std::string& msg);
    void packetDropped(const std::string& msg);

private:

    WebSocketClient& _ws_client;

    FirewallLogger(const FirewallLogger&) = delete;
    FirewallLogger& operator=(const FirewallLogger&) = delete;
    ~FirewallLogger() = default;

    FirewallLogger();
    std::string getCurrentTime();
    std::string convertMsgTojsonStr(const std::string& info_msg, const std::string& type);


};