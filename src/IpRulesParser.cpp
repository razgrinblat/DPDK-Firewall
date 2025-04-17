#include "IpRulesParser.hpp"

IpRulesParser & IpRulesParser::getInstance(const std::string& file_path)
{
    static IpRulesParser instance(file_path);
    return instance;
}

void IpRulesParser::loadRules()
{
    _current_rules.clear();
    _root.clear();
    openAndParseRulesFile();
    int rule_index = 1;
    static bool already_loaded = false;
    const Json::Value& rules = _root["rules"];
    for (const auto& rule : rules)
    {
        try {
            validateRule(rule);
            if(rule["is_active"].asBool())
            {
                const auto is_inserted = _current_rules.emplace_back(
                    rule["name"].asString(),
                    rule["protocol"].asString(),
                    rule["src_ip"].asString(),
                    rule["src_port"].asString(),
                    rule["dst_ip"].asString(),
                    rule["dst_port"].asString(),
                    rule["action"].asString());
            }
        }
        catch (const std::exception& e)
        {
            if (already_loaded)
            {
                std::cerr << "invalid rule [" << std::to_string(rule_index) << "]: " << e.what() << "\nRule: " << rule.
                    toStyledString() << std::endl;
            }
            else
            {
                throw std::invalid_argument(
                    "invalid rule [" + std::to_string(rule_index) + "]: " + e.what() + "\nRule: " + rule.
                    toStyledString());
            }
        }
        rule_index++;
    }
    already_loaded = true;
}

const std::vector<Rule> & IpRulesParser::getCurrentRules()
{
    return _current_rules;
}

IpRulesParser::IpRulesParser(const std::string& file_path): RulesParser(file_path)
{}

bool IpRulesParser::isValidIPv4(const std::string &ip)
{
    std::vector<std::string> ip_parts;
    std::stringstream ss(ip);
    std::string part;

    while (std::getline(ss,part,'.'))
    {
        ip_parts.push_back(part);
    }
    if (ip_parts.size() > 4) {
        return false;
    }
    for (const auto& octet : ip_parts)
    {
        if (octet == "*") { continue;}
        if (octet.empty() || octet.size() > 3) { return false;}
        for (const char c : octet)
        {
            if (!std::isdigit(c)) { return false;}
        }
        uint16_t value = std::stoi(octet);
        if (value < 0 || value > Config::MAX_IPV4_OCTET_NUMBER)
        {
            return false;
        }
    }
    return true;
}

void IpRulesParser::validateRule(const Json::Value& rule)
{
    const std::string action = rule["action"].asString();
    if (action != "block" && action != "accept")
    {
        throw std::invalid_argument("Field 'action' must be 'block' or 'accept'");
    }
    const std::string protocol = rule["protocol"].asString();
    if (protocol != "tcp" && protocol != "udp")
    {
        throw std::invalid_argument("Field 'protocol must be 'tcp' or 'udp'");
    }
    const std::string dst_ip = rule["dst_ip"].asString();
    if (!isValidIPv4(dst_ip))
    {
        throw std::invalid_argument("Invalid IPv4 Address");
    }
    if (rule["dst_port"].isInt())
    {
        const int port = rule["dst_port"].asInt();
        if (port < 1 || port > Config::MAX_PORT_NUMBER)
        {
            throw std::invalid_argument("Field 'port' must be a valid port number (1-65535), got: " + std::to_string(port));
        }
    }
    if (!rule["is_active"].isBool())
    {
        throw std::invalid_argument("Field 'is_active is a boolean");
    }
}

std::string IpRulesParser::convertPortToString(const Json::Value &dst_port)
{
    if (dst_port.isInt())
    {
        return std::to_string(dst_port.asInt());
    }
    return dst_port.asString();
}