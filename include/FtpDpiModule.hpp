#pragma once
#include <TcpReassembly.h>
#include "SessionTable.hpp"
#include "FtpRulesHandler.hpp"
#include "FirewallLogger.hpp"

class FtpDpiModule
{

private:
    SessionTable& _session_table;
    FtpRulesHandler& _ftp_rules_handler;


    FtpDpiModule();
    ~FtpDpiModule() = default;

    void processUploadFile(const std::string& upload_file, const pcpp::ConnectionData& conn_info);
    void processDownloadFile(const std::string& download_file, const pcpp::ConnectionData& conn_info);

public:
    FtpDpiModule(const FtpDpiModule&) = delete;
    FtpDpiModule& operator=(const FtpDpiModule&) = delete;
    static FtpDpiModule& getInstance();

    void onFtpMessageCallBack(const pcpp::TcpStreamData &tcpData);

};

