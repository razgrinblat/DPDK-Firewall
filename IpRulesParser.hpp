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
#include "RulesParser.hpp"
#include <unordered_set>
#include "Rule.hpp"

class IpRulesParser : public RulesParser
{
private:

    std::unordered_set<Rule> _current_rules;

    IpRulesParser(const std::string& file_path);
    bool isValidIPv4(const std::string& ip);
    void validateRule(const Json::Value& rule);
    std::string convertPortToString(const Json::Value& dst_port);

public:

    IpRulesParser(const IpRulesParser&) = delete;
    IpRulesParser& operator=(const IpRulesParser&) = delete;
    static IpRulesParser& getInstance(const std::string& file_path);

    void loadRules() override;
    const std::unordered_set<Rule>& getCurrentRules();

};
