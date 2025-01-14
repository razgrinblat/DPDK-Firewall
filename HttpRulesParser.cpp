#include "HttpRulesParser.hpp"

HttpRulesParser::HttpRulesParser(const std::string &file_path) : RulesParser(file_path), _http_rule_sets() {
}

void HttpRulesParser::loadSetFromJson(const Json::Value &json_array, std::unordered_set<std::string> &target_set,
                                      const std::string &field_name)
{
    for (const auto& item : json_array)
    {
        const auto is_inserted = target_set.insert(item.asString());
        if (!is_inserted.second)
        {
            throw std::invalid_argument("Warning! Duplicate value in " + field_name + ": " + item.asString());
        }
    }
}

void HttpRulesParser::loadHttpRules(const Json::Value &http_rules)
{
    loadSetFromJson(http_rules["hosts"], _http_rule_sets.url_hosts, "hosts");
    loadSetFromJson(http_rules["url_path_words"], _http_rule_sets.url_path_words, "url_path_words");
    loadSetFromJson(http_rules["content_types"], _http_rule_sets.content_types, "content_types");
    loadSetFromJson(http_rules["http_methods"], _http_rule_sets.http_methods, "http_methods");
    loadSetFromJson(http_rules["user_agents"], _http_rule_sets.user_agents, "user_agents");
    loadSetFromJson(http_rules["payload_words"], _http_rule_sets.payload_words, "payload_words");
}


HttpRulesParser & HttpRulesParser::getInstance(const std::string &file_path)
{
    static HttpRulesParser instance(file_path);
    return instance;
}

void HttpRulesParser::loadRules()
{
    _http_rule_sets.clear();
    _root.clear();
    static bool already_loaded = false;

    try
    {
        openAndParseRulesFile();
        const Json::Value& http_rules = _root["http_rules"];
        loadHttpRules(http_rules);

        if (http_rules.isMember("max_content_length") && http_rules["max_content_length"].isInt() && http_rules["max_content_length"].asInt() > 0)
        {
            _http_rule_sets.max_content_length = _root["max_content_length"].asInt();
        }
        else {
            _http_rule_sets.max_content_length = Config::DEFAULT_MAX_CONTENT_LENGTH;
        }
    }
    catch (const std::exception& e)
    {
        if (already_loaded)
        {
            std::cerr << e.what() << std::endl;
        }
        else
        {
            throw std::invalid_argument(e.what());
        }
    }
    already_loaded = true;
}

const HttpRulesParser::httpRule & HttpRulesParser::getHttpRules()
{
    return _http_rule_sets;
}
