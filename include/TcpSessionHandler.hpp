#pragma once
#include "PortAllocator.hpp"
#include <TcpLayer.h>
#include <memory>
#include <IPv4Layer.h>
#include <PacketUtils.h>
#include <SystemUtils.h>
#include "SessionTable.hpp"
#include "TcpCommonTypes.hpp"
#include "FtpControlHandler.hpp"

class TcpStateClass;

class TcpSessionHandler
{
private:
    SessionTable& _session_table;
    PortAllocator& _port_allocator;
    FtpControlHandler& _ftp_control_handler;

    TcpSessionHandler();

    bool isNewSession(const pcpp::tcphdr& tcp_header) const;
    bool isTerminationPacket(const pcpp::tcphdr& tcp_header) const;
    void setPassiveFtpSession(const std::unique_ptr<SessionTable::Session> &session);

    std::unique_ptr<SessionTable::Session> initTcpSession(const pcpp::Packet& tcp_packet) const;
    static const pcpp::tcphdr& extractTcpHeader(const pcpp::Packet& tcp_packet);

public:
    TcpSessionHandler(const TcpSessionHandler&) = delete;
    TcpSessionHandler& operator=(const TcpSessionHandler&) = delete;
    static TcpSessionHandler& getInstance();

    void processClientTcpPacket(pcpp::Packet& tcp_packet);
    void isValidInternetTcpPacket(pcpp::Packet& tcp_packet);
};