#pragma once
#include <HttpLayer.h>
#include <shared_mutex>
#include "InotifyWrapper.hpp"
#include "HttpRulesParser.hpp"

class HttpRulesHandler
{

private:
    HttpRulesParser& _http_rules_parser;
    HttpRulesParser::httpRule _http_rule;
    InotifyWrapper _file_watcher;
    std::shared_mutex _rules_mutex;

    HttpRulesHandler();
    void fileEventCallback();

    bool validateHostName(const pcpp::HeaderField* host_field) const;
    bool validateUrlPath(const std::string& url_path) const;
    bool validateContentType(const pcpp::HeaderField* type_field) const;
    bool validateUserAgent(const pcpp::HeaderField* user_agent) const;
    bool validateContentLength(const pcpp::HeaderField* content_length) const;


public:
    HttpRulesHandler(const HttpRulesHandler&) = delete;
    HttpRulesHandler& operator=(const HttpRulesHandler&) = delete;
    static HttpRulesHandler& getInstance();

    void buildRules();
    bool allowOutboundForwarding(const pcpp::HttpRequestLayer& request_layer);
    bool allowInboundForwarding(const pcpp::HttpResponseLayer& response_layer);
    std::optional<std::string> allowByPayloadForwarding(const std::string& payload_content);

};