#pragma once
#include <HttpLayer.h>
#include <mutex>
#include "InotifyWrapper.hpp"
#include "HttpRulesParser.hpp"

class HttpRulesHandler
{

private:
    HttpRulesParser& _http_rules_parser;
    InotifyWrapper _file_watcher;
    std::mutex _rules_mutex;

    HttpRulesHandler();
    void fileEventCallback();

public:
    HttpRulesHandler(const HttpRulesHandler&) = delete;
    HttpRulesHandler& operator=(const HttpRulesHandler&) = delete;
    static HttpRulesHandler& getInstance();

    void buildRules();
    bool allowOutboundForwarding(const pcpp::HttpRequestLayer& request_layer);
    bool allowInboundForwarding(const pcpp::HttpResponseLayer& response_layer);

};