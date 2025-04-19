#pragma once
#include <TcpReassembly.h>
#include <FtpLayer.h>
#include "SessionTable.hpp"


class FtpDpiModule
{

private:

    SessionTable& _session_table;
    std::unordered_map<uint32_t, std::string> _ftp_buffers;

    FtpDpiModule();
    ~FtpDpiModule() = default;


public:
    FtpDpiModule(const FtpDpiModule&) = delete;
    FtpDpiModule& operator=(const FtpDpiModule&) = delete;
    static FtpDpiModule& getInstance();

    void onFtpMessageCallBack(const pcpp::TcpStreamData &tcpData);

};

