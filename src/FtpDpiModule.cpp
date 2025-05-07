#include "FtpDpiModule.hpp"

FtpDpiModule::FtpDpiModule(): _session_table(SessionTable::getInstance()),
                              _ftp_rules_handler(FtpRulesHandler::getInstance())
{}

void FtpDpiModule::processUploadFile(const std::string &upload_file, const pcpp::ConnectionData& conn_info)
{
    if (upload_file.size() >= Config::DEFAULT_MAX_CONTENT_LENGTH)
    {
        _session_table.blockSession(conn_info.flowKey);
        FirewallLogger::getInstance().info("Session to -> Dst IP: " + conn_info.dstIP.toString() + " Dst Port: " +
            std::to_string(conn_info.dstPort)
        + " is closed! because:\n" + "file to upload is bigger than: " + std::to_string(Config::DEFAULT_MAX_CONTENT_LENGTH));
    }
    else if (const auto patterns = _ftp_rules_handler.allowByUploadFileContent(upload_file))
    {
        _session_table.blockSession(conn_info.flowKey);
        FirewallLogger::getInstance().info("Session to -> Dst IP: " + conn_info.dstIP.toString() + " Dst Port: " +
            std::to_string(conn_info.dstPort)
        + " is closed! because:\n" + patterns.value() + "in the file content");
    }
}

void FtpDpiModule::processDownloadFile(const std::string &download_file, const pcpp::ConnectionData& conn_info)
{
    if (download_file.size() >= Config::DEFAULT_MAX_CONTENT_LENGTH)
    {
        _session_table.blockSession(conn_info.flowKey);
        FirewallLogger::getInstance().info("Session to -> Dst IP: " + conn_info.srcIP.toString() + " Dst Port: " +
            std::to_string(conn_info.srcPort)
        + " is closed! because:\n" + "file to download is bigger than: " + std::to_string(Config::DEFAULT_MAX_CONTENT_LENGTH));
    }
    else if (const auto patterns = _ftp_rules_handler.allowByDownloadFileContent(download_file))
    {
        _session_table.blockSession(conn_info.flowKey);
        FirewallLogger::getInstance().info("Session to -> Dst IP: " + conn_info.srcIP.toString() + " Dst Port: " +
            std::to_string(conn_info.srcPort)
        + " is closed! because:\n" + patterns.value() + "in the file content");
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

    const auto& session = _session_table.getSession(session_key);
    std::string& ftp_frame = session->ftp_context.ftp_buffer;
    ftp_frame.append(reinterpret_cast<const char*>(data),data_length);

    const auto command = _session_table.getFtpRequestCommand(session_key).value();

    if (command == pcpp::FtpRequestLayer::FtpCommand::LIST)
    {
        std::cout <<"\n[LIST]\n" << ftp_frame  << "\n==================================\n" << std::endl;
    }
    else if (command == pcpp::FtpRequestLayer::FtpCommand::RETR)
    {
        FirewallLogger::getInstance().info("Client with Src IP: " + session->source_ip.toString() +
            " Downloaded file with this content:\n" + ftp_frame);
        processDownloadFile(ftp_frame,connection_data);
    }
    else if (command == pcpp::FtpRequestLayer::FtpCommand::STOR)
    {
        FirewallLogger::getInstance().info("Client with Src IP: " + session->source_ip.toString() +
            " Uploaded file with this content:\n" + ftp_frame);
        processUploadFile(ftp_frame,connection_data);
    }
}
