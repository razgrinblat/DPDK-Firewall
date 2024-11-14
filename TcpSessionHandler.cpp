#include "TcpSessionHandler.hpp"

TcpSessionHandler::TcpSessionHandler(): _session_table(SessionTable::getInstance()) {
}

TcpSessionHandler::~TcpSessionHandler() {
    
}

TcpSessionHandler & TcpSessionHandler::getInstance()
{
    static TcpSessionHandler instance;
    return instance;
}

void TcpSessionHandler::processClientTcpPacket(const pcpp::Packet &tcp_packet) {
}

void TcpSessionHandler::processInternetTcpPacket(const pcpp::Packet &tcp_packet) {
}
