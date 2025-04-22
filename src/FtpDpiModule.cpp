#include "FtpDpiModule.hpp"

FtpDpiModule::FtpDpiModule(): _session_table(SessionTable::getInstance())
{}

FtpDpiModule & FtpDpiModule::getInstance()
{
    static FtpDpiModule instance;
    return instance;
}

// handle data channel transfer.
void FtpDpiModule::onFtpMessageCallBack(const pcpp::TcpStreamData &tcpData)
{
    const uint32_t session_key  = tcpData.getConnectionData().flowKey;
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
    }
    else if (command == pcpp::FtpRequestLayer::FtpCommand::STOR)
    {
        std::cout <<"\n[UPLOAD]\n" << ftp_frame  << "\n==================================\n" << std::endl;
    }
}
