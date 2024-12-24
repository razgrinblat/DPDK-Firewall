#pragma once
#include <json/json.h>
#include <iostream>
#include <fstream>
#include <IpAddress.h>
#include <memory>
#include "Config.hpp"
#include <unordered_set>

struct Rule
{
    std::string protocol;
    std::string dst_ip;
    int dst_port;
    std::string action;

    Rule(const std::string& protocol, const std::string& dst_ip, const int dst_port, const std::string& action)
      : protocol(protocol), dst_ip(dst_ip), dst_port(dst_port), action(action){}

    bool operator==(const Rule& other) const {
        return protocol == other.protocol &&
               dst_ip == other.dst_ip &&
               dst_port == other.dst_port &&
               action == other.action;
    }

};



namespace std
{
    template<>
    struct hash<Rule> {
        std::size_t operator()(const Rule& rule) const {
            std::size_t h1 = std::hash<std::string>{}(rule.action);
            std::size_t h2 = std::hash<std::string>{}(rule.protocol);
            std::size_t h3 = std::hash<std::string>{}(rule.dst_ip);
            std::size_t h4 = std::hash<int>{}(rule.dst_port);
            return h1 ^ (h2 << 1) ^ (h3 << 2) ^ (h4 << 3);
        }
    };
}

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

    std::string _file_path;
    Json::Value _root;
    std::unordered_set<Rule> _current_rules;

    RulesParser(const std::string& file_path);
    bool isValidIp(const std::string& ip);
    void validateRule(const Json::Value& rule);
    void openAndParseRulesFile();

};
