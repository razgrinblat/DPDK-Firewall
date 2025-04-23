#include "FtpDpiModule.hpp"

FtpDpiModule::FtpDpiModule(): _session_table(SessionTable::getInstance()),
_ftp_rules_handler(FtpRulesHandler::getInstance())
{}

void FtpDpiModule::processUploadFile(const std::string &upload_file, const pcpp::ConnectionData& conn_info)
{
    if (const auto patterns = _ftp_rules_handler.allowByUploadFileContent(upload_file))
    {
        _session_table.blockSession(conn_info.flowKey);
        std::cout << "Session to -> Dst IP: " << conn_info.dstIP << " Dst Port: " << conn_info.dstPort
        << " is closed! because:\n" << patterns.value() << "in the file content" << std::endl;
    }
}

void FtpDpiModule::processDownloadFile(const std::string &download_file, const pcpp::ConnectionData& conn_info)
{
    if (const auto patterns = _ftp_rules_handler.allowByDownloadFileContent(download_file))
    {
        _session_table.blockSession(conn_info.flowKey);
        std::cout << "Session to -> Dst IP: " << conn_info.srcIP << " Dst Port: " << conn_info.srcPort
        << " is closed! because:\n" << patterns.value() << "in the file content" << std::endl;
    }
}

FtpDpiModule & FtpDpiModule::getInstance()
{
    static FtpDpiModule instance;
    return instance;
}

// handle data channel transfer.
void FtpDpiModule::onFtpMessageCallBack(const pcpp::TcpStreamData &tcpData)
{
    const pcpp::ConnectionData& connection_data = tcpData.getConnectionData();
    const uint32_t session_key  = connection_data.flowKey;
    const size_t data_length = tcpData.getDataLength();
    const auto data = tcpData.getData();

    std::string& ftp_frame = _session_table.getFtpBuffer(session_key);
    ftp_frame.append(reinterpret_cast<const char*>(data),data_length);

    const auto command = _session_table.getFtpRequestCommand(session_key).value();
    std::string com_str = pcpp::FtpRequestLayer::getCommandAsString(command);

    if (command == pcpp::FtpRequestLayer::FtpCommand::LIST)
    {
        std::cout <<"\n[LIST]\n" << ftp_frame  << "\n==================================\n" << std::endl;
    }
    else if (command == pcpp::FtpRequestLayer::FtpCommand::RETR)
    {
        std::cout <<"\n[DOWNLOAD]\n" << ftp_frame  << "\n==================================\n" << std::endl;
        processDownloadFile(ftp_frame,connection_data);
    }
    else if (command == pcpp::FtpRequestLayer::FtpCommand::STOR)
    {
        std::cout <<"\n[UPLOAD]\n" << ftp_frame  << "\n==================================\n" << std::endl;
        processUploadFile(ftp_frame,connection_data);
    }
}
