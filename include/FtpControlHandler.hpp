#pragma once
#include "FtpDpiModule.hpp"
#include <FtpLayer.h>
#include <IPv4Layer.h>


class FtpControlHandler
{

public:

    FtpControlHandler(const FtpControlHandler&) = delete;
    FtpControlHandler& operator=(const FtpControlHandler&) = delete;
    static FtpControlHandler& getInstance();

    void processFtpPacket(const pcpp::Packet& ftp_packet, uint32_t session_hash);

    /**
    * @brief Check if a packet in established state matches a known FTP passive data connection.
    * @param session Pointer to the session to check.
    * @param tcp_hash tcp 5-tuple hash
    * @return true if it's a passive FTP session, false otherwise.
    */
    void isPassiveFtpSession(const std::unique_ptr<SessionTable::Session>& session, uint32_t tcp_hash);


private:

    void handleFtpRequestCommand(const pcpp::FtpRequestLayer& request_layer, const pcpp::Packet& ftp_packet, uint32_t session_hash);

    void handleFtpResponseStatus(const pcpp::FtpResponseLayer& response_layer, const pcpp::Packet& ftp_packet, uint32_t session_hash);

    void createPassiveSessionEntry(const pcpp::FtpResponseLayer& response_layer, uint32_t session_hash);

    void setDataChannelStatus(uint32_t session_hash, pcpp::FtpRequestLayer::FtpCommand command);

    void validateUploadFileName(const std::string& upload_file_name, const std::string& packet_info);

    void validateDownloadFileName(const std::string& download_file_name, const std::string& packet_info);
    /**
     *
     * @param response a string of passive mode/active mode arguments such as - Entering Passive Mode (192,168,1,29,78,111)
     * @return vector of the wanted numbers
     */
    std::optional<std::vector<int>> extractFtpNumbers(const std::string& response);

    std::optional<std::pair<pcpp::IPv4Address, uint16_t>> parseFtpMessageToIpPort(const std::string& response);

    FtpControlHandler();
    ~FtpControlHandler() = default;



    // table of port to ip in order to identify passive mode FTP sessions
    std::unordered_map<PassiveKey,uint32_t> _passive_table; //passive data channel key to control session
    std::mutex _table_mutex;
    SessionTable& _session_table;
    static constexpr auto FTP_PORT_BASE = 256;

};