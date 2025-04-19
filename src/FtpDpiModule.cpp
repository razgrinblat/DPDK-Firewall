#include "FtpDpiModule.hpp"

FtpDpiModule & FtpDpiModule::getInstance()
{
    static FtpDpiModule instance;
    return instance;
}

//handle data channel transfer.
void FtpDpiModule::onFtpMessageCallBack(const pcpp::TcpStreamData &tcpData)
{
    const auto data = tcpData.getData();
    const std::string_view command = reinterpret_cast<const char*>(data);
    std::cout << command << std::endl;
}
