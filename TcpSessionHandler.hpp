#pragma once
#include "SessionTable.hpp"
#include "DpiEngine.hpp"
#include <Packet.h>
#include <IPv4Layer.h>
#include <TcpLayer.h>
#include <memory>
#include <PacketUtils.h>
#include <SystemUtils.h>
#include <DpdkDeviceList.h>
#include <DpdkDevice.h>
#include <EthLayer.h>

class TcpSessionHandler
{

private:
    SessionTable& _session_table;
    DpiEngine& _dpi_engine;

    TcpSessionHandler();
    std::unique_ptr<SessionTable::TcpSession> initTcpSession(const pcpp::Packet& tcp_packet, uint32_t seq_number, uint32_t ack_number);
    const pcpp::tcphdr& extractTcpHeader(const pcpp::Packet &tcp_packet);

public:
    ~TcpSessionHandler();
    TcpSessionHandler(const TcpSessionHandler&) = delete;
    TcpSessionHandler& operator=(const TcpSessionHandler&) = delete;
    static TcpSessionHandler& getInstance();

    bool processClientTcpPacket(pcpp::Packet& tcp_packet);
    bool processInternetTcpPacket(pcpp::Packet& tcp_packet);

};