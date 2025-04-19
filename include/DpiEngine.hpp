#pragma once
#include <HttpDpiModule.hpp>
#include <FtpDpiModule.hpp>
#include <FtpControlHandler.hpp>

class DpiEngine
{
private:
    pcpp::TcpReassembly _tcp_reassembly;  // Reassembles TCP HTTP/FTP streams.
    HttpDpiModule& _http_dpi_module;
    FtpDpiModule& _ftp_dpi_module;
    FtpControlHandler& _ftp_control_handler;

    /**
     * @brief Construct a new DpiEngine object.
     */
    DpiEngine();
    ~DpiEngine() = default;

    /**
     * @brief Callback function when a TCP reassembled stream is ready.
     *
     * @param sideIndex Indicates the TCP side (client/server).
     * @param tcpData The reassembled stream data.
     * @param userCookie Pointer to DpiEngine instance.
     */
    static void tcpReassemblyMsgReadyCallback(int8_t sideIndex, const pcpp::TcpStreamData& tcpData, void* userCookie);



public:
    DpiEngine(const DpiEngine&) = delete;
    DpiEngine& operator=(const DpiEngine&) = delete;

    /**
     * @brief Get the singleton instance of DpiEngine.
     *
     * @return DpiEngine& Reference to the singleton instance.
     */
    static DpiEngine& getInstance();

    /**
     * @brief Process a TCP packet through the DPI engine.
     *
     * @param tcp_packet The TCP packet to process.
     */
    void processDpiTcpPacket(pcpp::Packet& tcp_packet, bool ftp_inspection);
};