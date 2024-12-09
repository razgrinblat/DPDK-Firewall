#include "RulesParser.hpp"

RulesParser & RulesParser::getInstance()
{
    static RulesParser instance;
    return instance;
}

bool RulesParser::isValidIp(const std::string &ip)
{
    return pcpp::IPv4Address(ip).isValid();
}

void RulesParser::validateRule(const Json::Value& rule)
{
    const std::string action = rule["action"].asString();
    if (action != "block" && action != "accept")
    {
        throw std::invalid_argument("Field 'action' must be 'block or 'accept'");
    }
    const std::string dst_ip = rule["dst_ip"].asString();
    if (!isValidIp(dst_ip))
    {
        throw std::invalid_argument("Invalid IP");
    }
    if (!rule["dst_port"].isInt())
    {
        throw std::invalid_argument("Field 'port' must be an integer");
    }
    const int port = rule["dst_port"].asInt();
    if (port < 1 || port > 65535)
    {
        throw std::invalid_argument("Field 'port' must be a valid port number (1-65535), got: " + std::to_string(port));
    }
    if (!rule["is_active"].isBool())
    {
        throw std::invalid_argument("Field 'is_active is a boolean");
    }
}

void RulesParser::openAndParseRulesFile()
{
    std::ifstream file(FILE_PATH);
    if (!file.is_open()) {
        throw std::runtime_error("Failed to open firewall_rules.json");
    }
    Json::Reader reader;
    if (!reader.parse(file, _root)) {
        throw std::runtime_error("Error parsing JSON: " + reader.getFormattedErrorMessages());
    }
}

void RulesParser::loadRules()
{
    try {
        openAndParseRulesFile();
        int rule_index = 1;
        const Json::Value rules = _root["rules"];
        for (const auto& rule : rules)
        {
            try {
                validateRule(rule);
                std::string action = rule["action"].asString();
                std::string dst_ip = rule["dst_ip"].asString();
                std::string dst_port = rule["dst_port"].asString();
                bool is_active = rule["is_active"].asBool();

                std::cout << action << " " << dst_ip << " " << dst_port << " " << (is_active ? "true" : "false") << std::endl;
            }
            catch (const std::exception& e)
            {
                std::cerr  << "invalid rule" << "[" << rule_index << "]: " << e.what() << "\nRule: " << rule.toStyledString() << std::endl;
            }
            rule_index++;
        }
    }
    catch (const std::exception& e)
    {
        std::cerr << e.what() << std::endl;
        throw;
    }
}
