#pragma once
#include "SessionTable.hpp"
#include <UdpLayer.h>
#include <IPv4Layer.h>
#include <PacketUtils.h>
#include <SystemUtils.h>

class UdpSessionHandler
{

private:
    SessionTable& _session_table;
    PortAllocator& _port_allocator;

    UdpSessionHandler();
    std::unique_ptr<SessionTable::Session> initUdpSession(const pcpp::Packet& tcp_packet) const;

public:
    ~UdpSessionHandler() = default;
    UdpSessionHandler(const UdpSessionHandler&) = delete;
    UdpSessionHandler& operator=(const UdpSessionHandler&) = delete;
    static UdpSessionHandler& getInstance();

    void processClientUdpPacket(pcpp::Packet& udp_packet);
    void isValidInternetUdpPacket(pcpp::Packet& udp_packet);

};
