#include "DpiEngine.hpp"

DpiEngine::DpiEngine() : _http_reassembly(tcpReassemblyMsgReadyCallback,this)
{}

DpiEngine & DpiEngine::getInstance()
{
    static DpiEngine instance;
    return instance;
}

void DpiEngine::tcpReassemblyMsgReadyCallback(const int8_t sideIndex, const pcpp::TcpStreamData &tcpData,
    void *userCookie)
{
    const uint16_t dst_port = tcpData.getConnectionData().dstPort;
    if (dst_port == 80)
    {
        DpiEngine* dpi_engine = static_cast<DpiEngine*>(userCookie);
        const uint32_t session_key  = tcpData.getConnectionData().flowKey;
        const size_t data_length = tcpData.getDataLength();
        const auto data = tcpData.getData();

        // Append reassembled data to the buffer
        std::string& http_frame = dpi_engine->_http_buffers[session_key];
        http_frame.append(reinterpret_cast<const char*>(data),data_length);

        if (dpi_engine->isHttpMessageComplete(http_frame)) {

            std::cout << "=================HTTP-MESSAGE=================" << std::endl;
            std:: cout << dpi_engine->_http_buffers[session_key] << std::endl;

            dpi_engine->_http_buffers.erase(session_key);
        }
    }
}

void DpiEngine::processDpiTcpPacket(pcpp::Packet &tcp_packet)
{
    _http_reassembly.reassemblePacket(tcp_packet);
}

std::string DpiEngine::decompressGzip(const uint8_t *compress_data, const size_t compress_size) {
    if (compress_data == nullptr || compress_size == 0) {
        throw std::invalid_argument("Compressed data is null or empty");
    }

    z_stream stream{};
    stream.next_in = const_cast<Bytef*>(compress_data);
    stream.avail_in = static_cast<uInt>(compress_size);

    // Initialize with gzip decoding support
    if (inflateInit2(&stream, 16 + MAX_WBITS) != Z_OK) {
        throw std::runtime_error("Failed to initialize zlib for gzip decompression");
    }

    std::vector<char> decompressedData;
    char buffer[4096]; // Temporary buffer

    int ret;
    do {
        stream.next_out = reinterpret_cast<Bytef*>(buffer);
        stream.avail_out = sizeof(buffer);

        ret = inflate(&stream, Z_NO_FLUSH);
        if (ret == Z_STREAM_END) break;

        if (ret != Z_OK) {
            inflateEnd(&stream); // Cleanup
            std::cerr << "Error during gzip decompression: " << std::to_string(ret);
        }

        decompressedData.insert(decompressedData.end(), buffer, buffer + (sizeof(buffer) - stream.avail_out));
    } while (ret != Z_STREAM_END);

    inflateEnd(&stream); // Cleanup

    return std::string(decompressedData.begin(), decompressedData.end());
}

bool DpiEngine::isHttpMessageComplete(const std::string& http_frame) const
{
    // Create a RawPacket
    pcpp::RawPacket rawPacket(reinterpret_cast<const uint8_t*>(http_frame.data()), http_frame.size(), TIMEVAL_ZERO, false);
    pcpp::RawPacket raw_packet(reinterpret_cast<const uint8_t*>(http_frame.data()),http_frame.size(),TIMEVAL_ZERO,false);
    const pcpp::Packet packet(&raw_packet);

    pcpp::HttpMessage* http_message = packet.getLayerOfType<pcpp::HttpMessage>();

    if (!http_message->isHeaderComplete()) {
        return false;
    }

    if (packet.isPacketOfType(pcpp::HTTPRequest))
    {
        const auto http_request_layer = packet.getLayerOfType<pcpp::HttpRequestLayer>();
        if (http_request_layer->getFirstLine()->getMethod() == pcpp::HttpRequestLayer::HttpPOST)
        {
            const pcpp::HeaderField* content_field = http_request_layer->getFieldByName("Content-Length");
            if (content_field)
            {
                const size_t expectedBodySize = std::stoi(content_field->getFieldValue());
                const size_t actual_body_size = http_request_layer->getLayerPayloadSize();
                if (expectedBodySize == actual_body_size) {
                    return true;
                }
                return false;
            }
            std::cerr << "Content-Length header not found. Cannot determine completeness." << std::endl;
            return false;
        }
    }
    else if (packet.isPacketOfType(pcpp::HTTPResponse))
    {
        const auto http_response_layer = packet.getLayerOfType<pcpp::HttpResponseLayer>();
        pcpp::HeaderField* content_field = http_response_layer->getFieldByName("Content-Length");
        if (content_field)
        {
            const size_t expectedBodySize = std::stoi(content_field->getFieldValue());
            const size_t actual_body_size = http_response_layer->getLayerPayloadSize();
            if (expectedBodySize == actual_body_size) {
                return true;
            }
            return false;
        }
        const pcpp::HeaderField* encoding_field = http_response_layer->getFieldByName("Transfer-Encoding");
        if (encoding_field && encoding_field->getFieldValue() == "chunked")
        {
            // Retrieve the HTTP body
            uint8_t* body = http_response_layer->getLayerPayload();
            const size_t bodyLength = http_response_layer->getLayerPayloadSize();

            // Body is too short to contain the terminating chunk sequence
            if (bodyLength < 5) {
                return false;
            }

            // Check if the last characters of the body are "0\r\n\r\n"
            const std::string bodyStr(reinterpret_cast<char*>(body), bodyLength);
            if (bodyStr.substr(bodyLength - 5) == "0\r\n\r\n") {
                return true; // Message is complete
            }
            return false;
        }
    }
    std::cerr << "unValid http frame" << std::endl;
    return false;
}