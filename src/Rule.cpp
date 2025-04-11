#include "Rule.hpp"

Rule::Rule(const std::string& protocol, const std::string& dst_ip, const std::string& dst_port, const std::string& action)
    : protocol(protocol), dst_ip(dst_ip), dst_port(dst_port), action(action) {}

std::string Rule::getProtocol() const { return protocol; }
std::string Rule::getDstIp() const { return dst_ip; }
std::string Rule::getDstPort() const { return dst_port; }
bool Rule::getAction() const { return action != "block"; }

bool Rule::operator==(const Rule& other) const
{
    return protocol == other.protocol &&
           dst_ip == other.dst_ip &&
           dst_port == other.dst_port &&
           action == other.action;
}

std::string Rule::toString() const
{
    return "Protocol: " + protocol
       + ", Destination IP: " + dst_ip
       + ", Destination Port: " +dst_port
       + ", Action: " + action;
}

std::ostream& operator<<(std::ostream& os, const Rule& rule)
{
    os << "Protocol: " << rule.protocol
       << ", Destination IP: " << rule.dst_ip
       << ", Destination Port: " << rule.dst_port
       << ", Action: " << rule.action;
    return os;
}

size_t std::hash<Rule>::operator()(const Rule& rule) const
{
    return std::hash<std::string>{}(rule.getProtocol() + rule.getDstIp() + rule.getDstPort());
}
