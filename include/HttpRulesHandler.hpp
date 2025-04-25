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
    ~HttpRulesHandler() = default;
    void fileEventCallback();

    std::string httpMethodToString(pcpp::HttpRequestLayer::HttpMethod method);
    bool isValidMethod(pcpp::HttpRequestLayer::HttpMethod method);
    bool isValidHostName(const pcpp::HeaderField* host_field) const;
    bool isValidUrlPath(const std::string& url_path) const;
    bool isValidContentType(const pcpp::HeaderField* type_field) const;
    bool isValidUserAgent(const pcpp::HeaderField* user_agent) const;
    bool isValidContentLength(const pcpp::HeaderField* content_length) const;


public:
    HttpRulesHandler(const HttpRulesHandler&) = delete;
    HttpRulesHandler& operator=(const HttpRulesHandler&) = delete;
    static HttpRulesHandler& getInstance();

    void buildRules();
    std::optional<std::string> isValidRequest(const pcpp::HttpRequestLayer& request_layer);
    std::optional<std::string> isValidResponse(const pcpp::HttpResponseLayer& response_layer);
    std::optional<std::string> allowByPayloadForwarding(const std::string& payload_content);

};