#pragma once
#include <TcpReassembly.h>
#include <HttpLayer.h>
#include <zlib.h>
#include <iomanip>
#include <cstring>
#include <variant>
#include "SessionTable.hpp"
#include "HttpRulesHandler.hpp"

class DpiEngine
{
private:
    pcpp::TcpReassembly _http_reassembly;
    std::unordered_map<uint32_t, std::string> _http_buffers;
    SessionTable& _session_table;
    HttpRulesHandler& _http_rules_handler;

    DpiEngine();

    void processHttpRequest(const std::unique_ptr<pcpp::HttpRequestLayer>& request_layer, const std::string& http_msg, const pcpp::ConnectionData& tcp_data);
    void processHttpResponse(const std::unique_ptr<pcpp::HttpResponseLayer>& response_layer, const std::string& http_msg, const pcpp::ConnectionData& tcp_data);
    void processHttpMessage(const std::string& http_frame, const pcpp::ConnectionData& tcp_data);

    static void tcpReassemblyMsgReadyCallback(int8_t sideIndex, const pcpp::TcpStreamData& tcpData, void* userCookie);
    std::string decompressGzip(const uint8_t *compress_data, size_t compress_size);
    size_t findGzipHeaderOffset(const uint8_t* body, size_t body_length);
    std::unique_ptr<pcpp::HttpRequestLayer> createHttpRequestLayer(const std::string& http_message);
    std::unique_ptr<pcpp::HttpResponseLayer> createHttpResponseLayer(const std::string& http_message);
    std::optional<std::string> extractGzipContentFromResponse(const pcpp::HttpResponseLayer& response_layer);

    using httpLayerVariant = std::variant<std::unique_ptr<pcpp::HttpRequestLayer>, std::unique_ptr<pcpp::HttpResponseLayer>>;
    //return Request or Response HTTP Layer if the message is complete
    std::optional<httpLayerVariant> isHttpMessageComplete(const std::string& http_frame);

public:
    ~DpiEngine() = default;
    DpiEngine(const DpiEngine&) = delete;
    const DpiEngine& operator=(const DpiEngine&) = delete;
    static DpiEngine& getInstance();


    void processDpiTcpPacket(pcpp::Packet& tcp_packet);
};
