#pragma once
#include <iostream>
#include "Packet.h"

class PacketStats
{
private:
    uint32_t _ethPacketCount;
    uint32_t _ipv4PacketCount;
    uint32_t _ipv6PacketCount;
    uint32_t _tcpPacketCount;
    uint32_t _udpPacketCount;
    uint32_t _dnsPacketCount;
    uint32_t _httpPacketCount;
    uint32_t _sslPacketCount;
    uint32_t _arpPacketCount;
    uint32_t _icmpPacketCount;
    uint32_t _sshPacketCount;
    uint32_t _ftpPacketCount;

    PacketStats();

public:

    ~PacketStats() = default;
    PacketStats(const PacketStats&) = delete;
    PacketStats& operator=(const PacketStats&) = delete;
    static PacketStats& getInstance();

    void consumePacket(const pcpp::Packet& packet);

    void printToConsole() const;


};



