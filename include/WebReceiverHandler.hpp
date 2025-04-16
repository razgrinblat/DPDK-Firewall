#pragma once
#include <string>
#include <json/json.h>
#include <iostream>
#include <sstream>
#include "Config.hpp"
#include <fstream>


class WebReceiverHandler
{

public:

    WebReceiverHandler(const WebReceiverHandler&) = delete;
    WebReceiverHandler& operator=(const WebReceiverHandler&) = delete;
    static WebReceiverHandler& getInstance();

    void webMessageCallBack(const std::string& text);


private:

    void writeRulesToFile(const std::string& ip_rules, const std::string& file_path);
    WebReceiverHandler() = default;
    ~WebReceiverHandler() = default;

};
