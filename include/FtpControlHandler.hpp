#pragma once
#include "SessionTable.hpp"
#include "PortAllocator.hpp"
#include <FtpLayer.h>
#include <IPv4Layer.h>

class FtpControlHandler
{

public:
    FtpControlHandler(const FtpControlHandler&) = delete;
    FtpControlHandler& operator=(const FtpControlHandler&) = delete;
    static FtpControlHandler& getInstance();

    void handleFtpPacket(pcpp::Packet& ftp_packet);

    /**
    * @brief Check if a packet in established state matches a known FTP passive data connection.
    * @param session Pointer to the session to check.
    * @return true if it's a passive FTP session, false otherwise.
    */
    bool isPassiveFtpSession(const std::unique_ptr<SessionTable::Session>& session);


private:

    void handleFtpRequest(const pcpp::FtpRequestLayer& request_layer);

    void handleFtpResponse(const pcpp::FtpResponseLayer& response_layer);

    /**
     *
     * @param response a string of passive mode arguments such as - Entering Passive Mode (192,168,1,29,78,111)
     * @return vector of the wanted numbers
     */
    std::optional<std::vector<int>> extractPasvNumbers(const std::string& response);

    std::optional<std::pair<pcpp::IPv4Address, uint16_t>> parsePasvResponseToIpPort(const std::string& response);

    FtpControlHandler() = default;
    ~FtpControlHandler() = default;

    // table of port to ip in order to identify passive mode FTP sessions
    std::unordered_map<uint16_t,std::string> _passive_table;
    std::mutex _table_mutex;
};
