#include "FirewallLogger.hpp"

FirewallLogger & FirewallLogger::getInstance()
{
    static FirewallLogger instance;
    return instance;
}

void FirewallLogger::error(const std::string &msg)
{
    const std::string full_msg = getCurrentTime() + " [ERROR] " + msg;
    std::cerr << full_msg << std::endl;
}

void FirewallLogger::info(const std::string &msg)
{
    const std::string full_msg = getCurrentTime() + " [INFO] " + msg;
    std::cout << full_msg << std::endl;
    _ws_client.send(full_msg);
}

void FirewallLogger::packetDropped(const std::string &msg)
{
    const std::string full_msg = "[PACKET BLOCKED] " + msg;
    std::cout << full_msg << std::endl;
    _ws_client.send(full_msg);
}

FirewallLogger::FirewallLogger(): _ws_client(WebSocketClient::getInstance())
{}

std::string FirewallLogger::getCurrentTime()
{
    const auto now = std::chrono::system_clock::now();
    const auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()) % 1000;

    const std::time_t nowTime = std::chrono::system_clock::to_time_t(now);
    const std::tm* nowTm = std::localtime(&nowTime);

    std::stringstream ss;
    ss << "[" << std::put_time(nowTm, "%Y-%m-%d %H:%M:%S")
       << '.' << std::setfill('0') << std::setw(3) << ms.count() << "]";

    return ss.str();
}
