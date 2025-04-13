#pragma once
#include "PortAllocator.hpp"
#include <TcpLayer.h>
#include <memory>
#include <IPv4Layer.h>
#include <PacketUtils.h>
#include <SystemUtils.h>
#include "SessionTable.hpp"
#include "TcpCommonTypes.hpp"

class TcpStateClass;

class TcpSessionHandler
{
private:
    SessionTable& _session_table;
    PortAllocator& _port_allocator;

    TcpSessionHandler();

    bool isNewSession(const pcpp::tcphdr& tcp_header) const;
    bool isTerminationPacket(const pcpp::tcphdr& tcp_header) const;

    void processExistingSession(uint32_t hash, pcpp::Packet& tcp_packet, const pcpp::tcphdr& tcp_header, uint32_t size, bool is_outbound);
    std::unique_ptr<SessionTable::Session> initTcpSession(const pcpp::Packet& tcp_packet) const;
    static const pcpp::tcphdr& extractTcpHeader(const pcpp::Packet& tcp_packet);

public:
    static TcpSessionHandler& getInstance();

    void processClientTcpPacket(pcpp::Packet& tcp_packet);
    void isValidInternetTcpPacket(pcpp::Packet& tcp_packet);
};