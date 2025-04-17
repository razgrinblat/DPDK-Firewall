#pragma once
#include <string>
#include <iostream>

class Rule
{
private:
    std::string _name;
    std::string _protocol;
    std::string _src_ip;
    std::string _src_port;
    std::string _dst_ip;
    std::string _dst_port;
    std::string _action;

public:

    Rule(const std::string &name, const std::string &protocol,const std::string &src_ip, const std::string &src_port, const std::string &dst_ip, const std::string &dst_port,
         const std::string &action);
    ~Rule() = default;

    std::string getProtocol() const;
    std::string getSrcIp() const;
    std::string getSrcPort() const;
    std::string getDstIp() const;
    std::string getDstPort() const;
    bool getAction() const; //true - allow false - block;
    std::string getName() const;
    std::string toString() const;

    bool operator==(const Rule& other) const;

    friend std::ostream& operator<<(std::ostream& os, const Rule& rule);
};

namespace std {
    template <>
    struct hash<Rule> {
        std::size_t operator()(const Rule& rule) const;
    };
}