#pragma once
#include <string>
#include <iostream>

class Rule
{
private:
    std::string protocol;
    std::string dst_ip;
    std::string dst_port;
    std::string action;

public:

    Rule(const std::string& protocol, const std::string& dst_ip, const std::string& dst_port, const std::string& action);
    ~Rule() = default;

    std::string getProtocol() const;
    std::string getDstIp() const;
    std::string getDstPort() const;
    bool getAction() const; //true - allow false - block;
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