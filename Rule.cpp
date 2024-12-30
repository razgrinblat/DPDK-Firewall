#include "Rule.hpp"

Rule::Rule(const std::string& protocol, const std::string& dst_ip, const std::string& dst_port, const std::string& action)
    : protocol(protocol), dst_ip(dst_ip), dst_port(dst_port), action(action) {}

std::string Rule::getProtocol() const { return protocol; }
std::string Rule::getDstIp() const { return dst_ip; }
std::string Rule::getDstPort() const { return dst_port; }
std::string Rule::getAction() const { return action; }

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

std::ostream& operator<<(std::ostream& os, const Rule& rule) {
    os << "Protocol: " << rule.protocol
       << ", Destination IP: " << rule.dst_ip
       << ", Destination Port: " << rule.dst_port
       << ", Action: " << rule.action;
    return os;
}

std::size_t std::hash<Rule>::operator()(const Rule& rule) const {
    std::size_t h1 = std::hash<std::string>{}(rule.getProtocol());
    std::size_t h2 = std::hash<std::string>{}(rule.getDstIp());
    std::size_t h3 = std::hash<std::string>{}(rule.getDstPort());
    std::size_t h4 = std::hash<std::string>{}(rule.getAction());
    return h1 ^ (h2 << 1) ^ (h3 << 2) ^ (h4 << 3);
}
