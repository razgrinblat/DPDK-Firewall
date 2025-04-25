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

std::string HttpRulesHandler::httpMethodToString(const pcpp::HttpRequestLayer::HttpMethod method)
{
    using M = pcpp::HttpRequestLayer::HttpMethod;
    switch (method)
    {
        case M::HttpGET:     return "GET";
        case M::HttpHEAD:    return "HEAD";
        case M::HttpPOST:    return "POST";
        case M::HttpPUT:     return "PUT";
        case M::HttpDELETE:  return "DELETE";
        case M::HttpCONNECT: return "CONNECT";
        case M::HttpOPTIONS: return "OPTIONS";
        case M::HttpTRACE:   return "TRACE";
        case M::HttpPATCH:   return "PATCH";
        default:             return "UNKNOWN";
    }
}

bool HttpRulesHandler::isValidMethod(const pcpp::HttpRequestLayer::HttpMethod method)
{
    const std::string str_method = httpMethodToString(method);
    for (const auto& rule_method  : _http_rule.http_methods)
    {
        if ( str_method == rule_method) {
            return false;
        }
    }
    return true;
}

bool HttpRulesHandler::isValidHostName(const pcpp::HeaderField* host_field) const
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

bool HttpRulesHandler::isValidUrlPath(const std::string& url_path) const
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

bool HttpRulesHandler::isValidContentType(const pcpp::HeaderField* type_field) const
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

bool HttpRulesHandler::isValidUserAgent(const pcpp::HeaderField* user_agent) const
{
    if (user_agent != nullptr)
    {
        const auto& user_agents_set = _http_rule.user_agents;
        const std::string name = user_agent->getFieldValue() + " ";
        if (user_agents_set.find(name.substr(0,name.find(" "))) != user_agents_set.end())
        {
            return false;
        }
    }
    return true;
}

bool HttpRulesHandler::isValidContentLength(const pcpp::HeaderField* content_length) const
{
    if (content_length != nullptr)
    {
        try
        {
            if (std::stoi(content_length->getFieldValue()) > _http_rule.max_content_length)
            {
                return false;
            }
        }
        catch (...) { // content length is not a number, std::stoi exception
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

std::optional<std::string> HttpRulesHandler::isValidRequest(const pcpp::HttpRequestLayer& request_layer)
{
    std::shared_lock lock(_rules_mutex);

    //checking http method
    const auto method = request_layer.getFirstLine()->getMethod();
    if (!isValidMethod(method)) return {"HTTP METHOD: " + httpMethodToString(method)};

    //checking host name rule
    const pcpp::HeaderField* host_field = request_layer.getFieldByName(PCPP_HTTP_HOST_FIELD);
    if (!isValidHostName(host_field)) return {"Host Field: " + host_field->getFieldValue()};

    //checking URL path rule
    const std::string url = request_layer.getUrl();
    if (!isValidUrlPath(url)) return {"Url: " + url};

    //checking content type rule
    const pcpp::HeaderField* content_type = request_layer.getFieldByName(PCPP_HTTP_CONTENT_TYPE_FIELD);
    if (!isValidContentType(content_type)) return {"Content Type: " + content_type->getFieldValue()};

    //checking user agent rule
    const pcpp::HeaderField* user_agent = request_layer.getFieldByName(PCPP_HTTP_USER_AGENT_FIELD);
    if (!isValidUserAgent(user_agent)) return {"User Agent: " + user_agent->getFieldValue()};

    //checking content length rule
    const pcpp::HeaderField* content_length = request_layer.getFieldByName(PCPP_HTTP_CONTENT_LENGTH_FIELD);
    if (!isValidContentLength(content_length)) return {"Content Length: " + content_length->getFieldValue()};

    return {};
}

std::optional<std::string> HttpRulesHandler::isValidResponse(const pcpp::HttpResponseLayer &response_layer)
{
    std::shared_lock lock(_rules_mutex);

    //checking content type rule
    const pcpp::HeaderField* content_type = response_layer.getFieldByName(PCPP_HTTP_CONTENT_TYPE_FIELD);
    if (!isValidContentType(content_type)) return {"Content Type: " + content_type->getFieldValue()};

    //checking content length rule
    const pcpp::HeaderField* content_length = response_layer.getFieldByName(PCPP_HTTP_CONTENT_LENGTH_FIELD);
    if (!isValidContentLength(content_length)) return {"Content Length: " + content_length->getFieldValue()};

    return {};
}

std::optional<std::string> HttpRulesHandler::allowByPayloadForwarding(const std::string &payload_content)
{
    std::shared_lock lock(_rules_mutex);
    return _http_rules_parser.getHttpAhoCorasick().search(payload_content);
}
