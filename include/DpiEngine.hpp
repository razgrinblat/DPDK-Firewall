#pragma once
#include <TcpReassembly.h>
#include <HttpLayer.h>
#include <zlib.h>
#include <iomanip>
#include <cstring>
#include <variant>
#include "SessionTable.hpp"
#include "HttpRulesHandler.hpp"

/**
 * @class DpiEngine
 * @brief Deep Packet Inspection engine for processing HTTP traffic.
 *
 * This singleton class handles TCP reassembly and inspects HTTP requests and responses,
 * applying rule-based filtering and gzip decompression when necessary.
 */
class DpiEngine
{
private:
    pcpp::TcpReassembly _http_reassembly;  // Reassembles TCP HTTP streams.
    SessionTable& _session_table;
    HttpRulesHandler& _http_rules_handler;
    std::unordered_map<uint32_t, std::string> _http_buffers; // Buffers for partially reassembled HTTP sessions.
    static constexpr std::string_view http_chunked_tail = "\r\n0\r\n\r\n";

    using httpLayerVariant = std::variant<std::unique_ptr<pcpp::HttpRequestLayer>, std::unique_ptr<pcpp::HttpResponseLayer>>;

    /**
     * @brief Construct a new DpiEngine object.
     */
    DpiEngine();

    /**
     * @brief Callback function when a TCP reassembled stream is ready.
     *
     * @param sideIndex Indicates the TCP side (client/server).
     * @param tcpData The reassembled stream data.
     * @param userCookie Pointer to DpiEngine instance.
     */
    static void tcpReassemblyMsgReadyCallback(int8_t sideIndex, const pcpp::TcpStreamData& tcpData, void* userCookie);

    /**
     * @brief Process an HTTP message (either request or response).
     *
     * @param http_frame Full HTTP message as string.
     * @param tcp_data TCP connection metadata.
     */
    void processHttpMessage(const std::string& http_frame, const pcpp::ConnectionData& tcp_data);

    /**
     * @brief Process an HTTP request and apply outbound rules.
     *
     * @param request_layer HTTP request layer.
     * @param http_msg Raw HTTP message.
     * @param tcp_data TCP connection metadata.
     */
    void processHttpRequest(const std::unique_ptr<pcpp::HttpRequestLayer>& request_layer,
                            const std::string& http_msg,
                            const pcpp::ConnectionData& tcp_data);

    /**
     * @brief Process an HTTP response and apply inbound rules.
     *
     * @param response_layer HTTP response layer.
     * @param http_msg Raw HTTP message.
     * @param tcp_data TCP connection metadata.
     */
    void processHttpResponse(const std::unique_ptr<pcpp::HttpResponseLayer>& response_layer,
                             const std::string& http_msg,
                             const pcpp::ConnectionData& tcp_data);

    /**
     * @brief Determine if an HTTP message is complete.
     *
     * @param http_frame Raw HTTP message.
     * @return Optional variant containing parsed HTTP layer.
     */
    std::optional<httpLayerVariant> isHttpMessageComplete(const std::string& http_frame);

    /**
     * @brief Handle a complete HTTP request message.
     *
     * @param http_frame HTTP request string.
     * @return Optional variant containing the parsed request layer.
     */
    std::optional<httpLayerVariant> handleHttpRequest(const std::string& http_frame);

    /**
     * @brief Handle a complete HTTP response message.
     *
     * @param http_frame HTTP response string.
     * @return Optional variant containing the parsed response layer.
     */
    std::optional<httpLayerVariant> handleHttpResponse(const std::string& http_frame);

    /**
     * @brief Create HttpRequestLayer from raw HTTP message.
     *
     * @param http_message Raw HTTP request string.
     * @return Unique pointer to HttpRequestLayer.
     */
    std::unique_ptr<pcpp::HttpRequestLayer> createHttpRequestLayer(const std::string& http_message);

    /**
     * @brief Create HttpResponseLayer from raw HTTP message.
     *
     * @param http_message Raw HTTP response string.
     * @return Unique pointer to HttpResponseLayer.
     */
    std::unique_ptr<pcpp::HttpResponseLayer> createHttpResponseLayer(const std::string& http_message);

    /**
     * @brief Extract and decompress gzip-encoded content.
     *
     * @param response_layer HTTP response layer to analyze.
     * @return Optional decompressed HTML content.
     */
    std::optional<std::string> extractGzipContentFromResponse(const pcpp::HttpResponseLayer& response_layer);

    /**
     * @brief Decompress gzip buffer.
     *
     * @param compress_data Pointer to compressed data.
     * @param compress_size Size of compressed data.
     * @return Decompressed string.
     */
    std::string decompressGzip(const uint8_t* compress_data, size_t compress_size);

    /**
     * @brief Find offset of Gzip header in buffer.
     *
     * @param body Pointer to buffer.
     * @param body_length Buffer length.
     * @return Offset of gzip header.
     */
    size_t findGzipHeaderOffset(const uint8_t* body, size_t body_length);

    /**
     * @brief Check if chunked transfer is complete.
     *
     * @param body Pointer to buffer.
     * @param length Buffer length.
     * @return True if chunked transfer ends with terminator.
     */
    bool hasChunkedTerminator(const uint8_t* body, size_t length);

    /**
     * @brief Validate Content-Length field.
     *
     * @param field Content-Length header field.
     * @param actualPayloadSize Actual payload size.
     * @return True if content length is complete.
     */
    bool isContentLengthComplete(const pcpp::HeaderField* field, size_t actualPayloadSize);

public:
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
    void processDpiTcpPacket(pcpp::Packet& tcp_packet);
};