#pragma once
#include <json/json.h>
#include <iostream>
#include <fstream>
#include <IpAddress.h>
#include <memory>
#include "Config.hpp"

class RulesParser
{
public:
    struct Rule
    {
        std::string action;
        std::string protocol;
        std::string dst_ip;
        int dst_port;

        Rule(const std::string& action, const std::string& protocol, const std::string& dst_ip, const int dst_port)
          : action(action),protocol(protocol), dst_ip(dst_ip), dst_port(dst_port){}
    };

    ~RulesParser() = default;
    RulesParser(const RulesParser&) = delete;
    RulesParser& operator=(const RulesParser&) = delete;
    static RulesParser& getInstance(const std::string& file_path);

    const std::vector<std::unique_ptr<Rule>>& getRules();

private:

    std::string _file_path;
    Json::Value _root;
    std::vector<std::unique_ptr<Rule>> _rules;

    RulesParser(const std::string& file_path);
    bool isValidIp(const std::string& ip);
    void validateRule(const Json::Value& rule);
    void openAndParseRulesFile();
    void loadRules();


};
