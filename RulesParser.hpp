#pragma once
#include <json/json.h>
#include <iostream>
#include <fstream>
#include <IpAddress.h>
#include <memory>
#include "Config.hpp"
#include <unordered_set>
#include "Rule.hpp"

class RulesParser
{
public:

    ~RulesParser() = default;
    RulesParser(const RulesParser&) = delete;
    RulesParser& operator=(const RulesParser&) = delete;
    static RulesParser& getInstance(const std::string& file_path);

    void loadRules();
    std::unordered_set<Rule>& getCurrentRules();


private:

    std::ifstream _file;
    Json::Value _root;
    std::unordered_set<Rule> _current_rules;

    RulesParser(const std::string& file_path);
    bool isValidIp(const std::string& ip);
    void validateRule(const Json::Value& rule);
    void openAndParseRulesFile();

};
