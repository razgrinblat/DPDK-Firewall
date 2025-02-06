#pragma once
#include "SessionTable.hpp"
#include "DpiEngine.hpp"
#include <TcpLayer.h>
#include <memory>
#include <PacketUtils.h>
#include <SystemUtils.h>

class TcpSessionHandler
{

private:
    SessionTable& _session_table;
    DpiEngine& _dpi_engine;
    PortAllocator& _port_allocator;

    TcpSessionHandler();
    std::unique_ptr<SessionTable::Session> initTcpSession(const pcpp::Packet& tcp_packet) const;
    const pcpp::tcphdr& extractTcpHeader(const pcpp::Packet &tcp_packet);

public:
    ~TcpSessionHandler() = default;
    TcpSessionHandler(const TcpSessionHandler&) = delete;
    TcpSessionHandler& operator=(const TcpSessionHandler&) = delete;
    static TcpSessionHandler& getInstance();

    bool processClientTcpPacket(pcpp::Packet& tcp_packet);
    bool isValidInternetTcpPacket(pcpp::Packet& tcp_packet);

};