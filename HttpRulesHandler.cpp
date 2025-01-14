#include "HttpRulesHandler.hpp"

HttpRulesHandler::HttpRulesHandler() : _http_rules_parser(HttpRulesParser::getInstance(Config::HTTP_RULES_PATH))
{
    _file_watcher.addWatch(Config::HTTP_RULES_PATH, std::bind(&HttpRulesHandler::fileEventCallback,this));
    _file_watcher.startWatching();
}

void HttpRulesHandler::fileEventCallback()
{
    std::unique_lock lock(_rules_mutex);
    _http_rules_parser.loadRules();
    _http_rule = _http_rules_parser.getHttpRules();
}

bool HttpRulesHandler::validateHostName(const pcpp::HeaderField* host_field) const
{
    if (host_field != nullptr)
    {
        const auto& host_set = _http_rule.url_hosts;
        if(host_set.find(host_field->getFieldValue()) != host_set.end())
        {
            return false;
        }
    }
    return true;
}

bool HttpRulesHandler::validateUrlPath(const std::string& url_path) const
{
    const auto& url_words_set = _http_rule.url_path_words;
    for (const auto& word : url_words_set)
    {
        if (url_path.find(word) != std::string::npos)
        {
            return false;
        }
    }
    return true;
}

bool HttpRulesHandler::validateContentType(const pcpp::HeaderField* type_field) const
{
    if (type_field != nullptr)
    {
        const auto& content_set = _http_rule.content_types;
        if (content_set.find(type_field->getFieldValue()) != content_set.end())
        {
            return false;
        }
    }
    return true;
}

bool HttpRulesHandler::validateUserAgent(const pcpp::HeaderField* user_agent) const
{
    if (user_agent != nullptr)
    {
        const auto& user_agents_set = _http_rule.user_agents;
        const std::string name = user_agent->getFieldName() + " ";
        if (user_agents_set.find(name.substr(0,name.find(" "))) != user_agents_set.end())
        {
            return false;
        }
    }
    return true;
}

bool HttpRulesHandler::validateContentLength(const pcpp::HeaderField* content_length) const
{
    if (content_length != nullptr)
    {
        try
        {
            if (std::stoi(content_length->getFieldName()) > _http_rule.max_content_length)
            {
                return false;
            }
        }
        catch (...) { // content length in not a number, std::stoi exception
            return false;
        }
    }
    return true;
}

HttpRulesHandler & HttpRulesHandler::getInstance()
{
    static HttpRulesHandler instance;
    return instance;
}

void HttpRulesHandler::buildRules()
{
    _http_rules_parser.loadRules();
    _http_rule = _http_rules_parser.getHttpRules();
    std::cout << "HTTP Rules built Successfully!" << std::endl;
}

bool HttpRulesHandler::allowOutboundForwarding(const pcpp::HttpRequestLayer& request_layer)
{
    std::shared_lock lock(_rules_mutex);
    //checking host name rule
    if (!validateHostName(request_layer.getFieldByName(PCPP_HTTP_HOST_FIELD))) return false;

    //checking URL path rule
    if (!validateUrlPath(request_layer.getUrl())) return false;

    //checking content type rule
    if (!validateContentType(request_layer.getFieldByName(PCPP_HTTP_CONTENT_TYPE_FIELD))) return false;

    //checking user agent rule
    if (!validateUserAgent(request_layer.getFieldByName(PCPP_HTTP_USER_AGENT_FIELD))) return false;

    //checking content length rule
    if (!validateContentLength(request_layer.getFieldByName(PCPP_HTTP_CONTENT_LENGTH_FIELD))) return false;
    return true;
}

bool HttpRulesHandler::allowInboundForwarding(const pcpp::HttpResponseLayer &response_layer)
{
    std::shared_lock lock(_rules_mutex);

}
