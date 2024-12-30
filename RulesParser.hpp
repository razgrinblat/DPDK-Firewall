#pragma once
#include <json/json.h>
#include <iostream>
#include <fstream>
#include <IpAddress.h>
#include <memory>
#include <vector>
#include <cctype>
#include <sstream>
#include "Config.hpp"
#include <unordered_set>
#include "Rule.hpp"

class RulesParser
{
private:

    std::ifstream _file;
    Json::Value _root;
    std::unordered_set<Rule> _current_rules;

    RulesParser(const std::string& file_path);
    bool isValidIPv4(const std::string& ip);
    void validateRule(const Json::Value& rule);
    void openAndParseRulesFile();
    std::string convertPortToString(const Json::Value& dst_port);

public:

    ~RulesParser() = default;
    RulesParser(const RulesParser&) = delete;
    RulesParser& operator=(const RulesParser&) = delete;
    static RulesParser& getInstance(const std::string& file_path);

    void loadRules();
    const std::unordered_set<Rule>& getCurrentRules();

};
