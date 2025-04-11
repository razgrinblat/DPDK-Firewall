#pragma once
#include "PortAllocator.hpp"
#include <TcpLayer.h>
#include <memory>
#include <IPv4Layer.h>
#include <PacketUtils.h>
#include <SystemUtils.h>
#include <DpiEngine.hpp>
#include "SessionTable.hpp"
#include "TcpCommonTypes.hpp"

class TcpStateClass;

class TcpSessionHandler
{
private:
    SessionTable& _session_table;
    DpiEngine& _dpi_engine;
    PortAllocator& _port_allocator;

    TcpSessionHandler();
    std::unique_ptr<SessionTable::Session> initTcpSession(const pcpp::Packet& tcp_packet) const;
    static const pcpp::tcphdr& extractTcpHeader(const pcpp::Packet& tcp_packet);

public:
    static TcpSessionHandler& getInstance();

    void updateSession(uint32_t tcp_hash, SessionTable::TcpState new_state, uint32_t packet_size, bool is_outbound);
    void processClientTcpPacket(pcpp::Packet& tcp_packet);
    void isValidInternetTcpPacket(pcpp::Packet& tcp_packet);
};