#pragma once
#include "SessionTable.hpp"
#include <Packet.h>
class TcpSessionHandler
{

private:
    SessionTable& _session_table;

    TcpSessionHandler();

public:
    ~TcpSessionHandler();
    TcpSessionHandler(const TcpSessionHandler&) = delete;
    TcpSessionHandler& operator=(const TcpSessionHandler&) = delete;
    static TcpSessionHandler& getInstance();

    void processClientTcpPacket(const pcpp::Packet& tcp_packet);
    void processInternetTcpPacket(const pcpp::Packet& tcp_packet);

};

