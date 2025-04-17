#include "Rule.hpp"

Rule::Rule(const std::string &name, const std::string &protocol,const std::string &src_ip, const std::string &src_port, const std::string &dst_ip, const std::string &dst_port,
         const std::string &action)
    : _name(name), _protocol(protocol), _src_ip(src_ip), _src_port(src_port), _dst_ip(dst_ip), _dst_port(dst_port), _action(action) {}

std::string Rule::getProtocol() const { return _protocol; }
std::string Rule::getSrcIp() const { return _src_ip; }
std::string Rule::getSrcPort() const {return _src_port; }
std::string Rule::getDstIp() const { return _dst_ip; }
std::string Rule::getDstPort() const { return _dst_port; }
bool Rule::getAction() const { return _action == "accept"; }
std::string Rule::getName() const {return _name;}

bool Rule::operator==(const Rule& other) const
{
    return  _src_ip == other._src_ip &&
            _src_port == other._src_port &&
            _protocol == other._protocol &&
           _dst_ip == other._dst_ip &&
           _dst_port == other._dst_port &&
           _action == other._action;
}

std::string Rule::toString() const
{
    return "Protocol: " + _protocol
       + ", Source IP: " + _src_ip
       + ", Source Port: " + _src_port
       + ", Destination IP: " + _dst_ip
       + ", Destination Port: " + _dst_port
       + ", Action: " + _action;
}

std::ostream& operator<<(std::ostream& os, const Rule& rule)
{
    os << "Protocol: " << rule._protocol
       << ", Source IP: " << rule._src_ip
       << ", Source Port: " << rule._src_port
       << ", Destination IP: " << rule._dst_ip
       << ", Destination Port: " << rule._dst_port
       << ", Action: " << rule._action;
    return os;
}

size_t std::hash<Rule>::operator()(const Rule& rule) const
{
    return std::hash<std::string>{}(rule.getProtocol() + rule.getSrcIp() + rule.getSrcPort() + rule.getDstIp() + rule.getDstPort());
}
