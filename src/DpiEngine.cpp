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

    if (conn.dstPort == Config::HTTP_PORT)
    {
        dpi_engine->_http_dpi_module.onHttpMessageCallBack(tcpData);
    }
    else if (conn.srcPort == Config::FTP_PORT || conn.dstPort == Config::FTP_PORT)
    {
        dpi_engine->_ftp_dpi_module.onFtpMessageCallBack(tcpData); // print control commands
    }
    else {
        const auto data = tcpData.getData();
        const std::string_view file = reinterpret_cast<const char*>(data);
        std::cout << file << std::endl;
    }
}

void DpiEngine::processDpiTcpPacket(pcpp::Packet &tcp_packet, bool ftp_inspection)
{
    if (tcp_packet.isPacketOfType(pcpp::HTTP))
    {
        _tcp_reassembly.reassemblePacket(tcp_packet);
    }
    else if (tcp_packet.isPacketOfType(pcpp::FTP)) //handle ftp control channel
    {
        _ftp_control_handler.handleFtpPacket(tcp_packet);
    }
    else if(ftp_inspection)
    {
        _tcp_reassembly.reassemblePacket(tcp_packet);
    }
}