#pragma once
#include <json/json.h>
#include <iostream>
#include <fstream>
#include <IpAddress.h>
class RulesParser
{
private:
    static auto constexpr FILE_PATH = "/tmp/tmp.CcQ3HkWRG0/DPDK-Firewall/firewall_rules.json";
    Json::Value _root;


    RulesParser() = default;
    bool isValidIp(const std::string& ip);
    void validateRule(const Json::Value& rule);
    void openAndParseRulesFile();

public:
    ~RulesParser() = default;
    RulesParser(const RulesParser&) = delete;
    RulesParser& operator=(const RulesParser&) = delete;
    static RulesParser& getInstance();

    void loadRules();
};
