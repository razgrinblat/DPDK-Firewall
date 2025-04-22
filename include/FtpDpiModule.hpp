#pragma once
#include <TcpReassembly.h>
#include "SessionTable.hpp"


class FtpDpiModule
{

private:
    SessionTable& _session_table;

    FtpDpiModule();
    ~FtpDpiModule() = default;


public:
    FtpDpiModule(const FtpDpiModule&) = delete;
    FtpDpiModule& operator=(const FtpDpiModule&) = delete;
    static FtpDpiModule& getInstance();

    void onFtpMessageCallBack(const pcpp::TcpStreamData &tcpData);

};

