#include "RulesParser.hpp"

RulesParser & RulesParser::getInstance(const std::string& file_path)
{
    static RulesParser instance(file_path);
    return instance;
}

RulesParser::RulesParser(const std::string &file_path): _file_path(file_path)
{
    loadRules();
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
    const std::string protocol = rule["protocol"].asString();
    if (protocol != "tcp" && protocol != "udp")
    {
        throw std::invalid_argument("Field 'protocol must be 'tcp' or 'udp'");
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
    if (port < 1 || port > Config::MAX_PORT_NUMBER)
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
    std::ifstream file(_file_path);
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
                if(rule["is_active"].asBool())
                {
                    _rules.emplace_back(std::make_unique<Rule>(

                rule["protocol"].asString(),
                rule["dst_ip"].asString(),
                rule["dst_port"].asInt(),
                rule["action"].asString()
                ));
                }
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

    }
}

std::vector<std::unique_ptr<RulesParser::Rule>> RulesParser::getRules()
{
    return std::move(_rules);
}
