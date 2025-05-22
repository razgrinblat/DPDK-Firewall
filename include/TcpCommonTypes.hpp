#pragma once

// This file contains only shared enums and types needed by multiple classes

namespace TCP_COMMON_TYPES
{
    enum TcpState
    {
        SYN_SENT,
        SYN_RECEIVED,
        ESTABLISHED,
        FIN_WAIT1,
        FIN_WAIT2,
        CLOSE_WAIT,
        TIME_WAIT,
        LAST_ACK,
        UNKNOWN,
    };

    enum Protocol
    {
        TCP_PROTOCOL,
        UDP_PROTOCOL
    };

}

struct PassiveKey
{
    pcpp::IPv4Address serverIp;
    uint16_t port;

    bool operator==(const PassiveKey& other) const {
        return serverIp == other.serverIp && port == other.port;
    }
    PassiveKey(const pcpp::IPv4Address ip, const uint16_t port) : serverIp(ip),port(port){}
};

namespace std {
    template <>
    struct hash<PassiveKey> {
        size_t operator()(const PassiveKey& k) const {
            return hash<uint32_t>()(k.serverIp.toInt()) ^ hash<uint16_t>()(k.port);
        }
    };
}
