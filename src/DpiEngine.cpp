#include "DpiEngine.hpp"

DpiEngine::DpiEngine() : _tcp_reassembly(tcpReassemblyMsgReadyCallback, this),
                         _http_dpi_module(HttpDpiModule::getInstance()), _ftp_dpi_module(FtpDpiModule::getInstance()),
                         _ftp_control_handler(FtpControlHandler::getInstance())
{}

DpiEngine & DpiEngine::getInstance()
{
    static DpiEngine instance;
    return instance;
}

void DpiEngine::tcpReassemblyMsgReadyCallback(const int8_t sideIndex, const pcpp::TcpStreamData &tcpData,
                                              void *userCookie)
{
    const pcpp::ConnectionData& conn = tcpData.getConnectionData();
    const DpiEngine* dpi_engine = static_cast<DpiEngine*>(userCookie);


    //DPI to HTTP
    if (conn.dstPort == Config::HTTP_PORT)
    {
        dpi_engine->_http_dpi_module.onHttpMessageCallBack(tcpData);
    }
    // DPI to FTP data sessions
    else if (SessionTable::getInstance().isFtpDataSession(conn.flowKey))
    {
        dpi_engine->_ftp_dpi_module.onFtpMessageCallBack(tcpData);
    }
}

void DpiEngine::processDpiTcpPacket(pcpp::Packet &tcp_packet, const uint32_t session_hash)
{
    if (tcp_packet.isPacketOfType(pcpp::FTP)) //handle ftp control channel
    {
        _ftp_control_handler.processFtpPacket(tcp_packet, session_hash);
    }
    else
    {
        _tcp_reassembly.reassemblePacket(tcp_packet);
    }
}