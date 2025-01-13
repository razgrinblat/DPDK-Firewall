#include "HttpRulesHandler.hpp"

HttpRulesHandler::HttpRulesHandler() : _http_rules_parser(HttpRulesParser::getInstance(Config::HTTP_RULES_PATH))
{
    _file_watcher.addWatch(Config::HTTP_RULES_PATH, std::bind(&HttpRulesHandler::fileEventCallback,this));
    _file_watcher.startWatching();
}

void HttpRulesHandler::fileEventCallback()
{
    std::lock_guard lock_guard(_rules_mutex);
    _http_rules_parser.loadRules();
}

HttpRulesHandler & HttpRulesHandler::getInstance()
{
    static HttpRulesHandler instance;
    return instance;
}

void HttpRulesHandler::buildRules()
{
    _http_rules_parser.loadRules();
    std::cout << "HTTP Rules built Successfully!" << std::endl;
}

bool HttpRulesHandler::allowOutboundForwarding(const pcpp::HttpRequestLayer &request_layer)
{


}

bool HttpRulesHandler::allowInboundForwarding(const pcpp::HttpResponseLayer &response_layer)
{

}
