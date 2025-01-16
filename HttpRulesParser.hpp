#pragma once
#include "RulesParser.hpp"
#include "Config.hpp"
#include <unordered_set>
#include <iostream>

class HttpRulesParser : public RulesParser
{
public:
    struct httpRule
    {
        std::unordered_set<std::string> url_hosts;
        std::unordered_set<std::string> url_path_words;
        std::unordered_set<std::string> content_types;
        std::unordered_set<std::string> http_methods;
        std::unordered_set<std::string> user_agents;
        std::unordered_set<std::string> payload_words;
        size_t max_content_length;

        void clear()
        {
            url_hosts.clear(), url_path_words.clear(), content_types.clear(),
            http_methods.clear(), user_agents.clear(), payload_words.clear();
        }
    };

    HttpRulesParser(const HttpRulesParser&) = delete;
    HttpRulesParser& operator=(const HttpRulesParser&) = delete;
    static HttpRulesParser& getInstance(const std::string& file_path);

    void loadRules() override;
    const httpRule& getHttpRules();

private:

    httpRule _http_rule_sets;

    HttpRulesParser(const std::string& file_path);

    void loadSetFromJson(const Json::Value& json_array, std::unordered_set<std::string>& target_set, const std::string& field_name);
    void loadHttpRules(const Json::Value& http_rules);



};
