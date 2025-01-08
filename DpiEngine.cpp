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
    if (tcpData.getConnectionData().dstPort == Config::HTTP_PORT)
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
            std:: cout << http_frame << std::endl;

            dpi_engine->_http_buffers.erase(session_key);
        }
    }
}

void DpiEngine::processDpiTcpPacket(pcpp::Packet &tcp_packet)
{
    _http_reassembly.reassemblePacket(tcp_packet);
}

std::string DpiEngine::decompressGzip(const uint8_t* compress_data, const size_t compress_size) {
    constexpr size_t bufferSize = 1024;
    char buffer[bufferSize];
    std::string decompressedData;

    z_stream stream{};
    stream.next_in = const_cast<Bytef*>(compress_data); // Input compressed data
    stream.avail_in = compress_size; // Size of the compressed data

    // Initialize the zlib stream with Gzip decoding
    if (inflateInit2(&stream, 16 + MAX_WBITS) != Z_OK) {
        throw std::runtime_error("Failed to initialize zlib for Gzip decompression");
    }

    try {
        do {
            stream.next_out = reinterpret_cast<Bytef*>(buffer); // Output buffer
            stream.avail_out = bufferSize; // Size of the output buffer

            int ret = inflate(&stream, Z_NO_FLUSH);

            if (ret != Z_OK && ret != Z_STREAM_END) {
                throw std::runtime_error("Decompression failed");
            }

            decompressedData.append(buffer, bufferSize - stream.avail_out);

            if (ret == Z_STREAM_END) {
                break;
            }
        } while (stream.avail_out == 0);

        inflateEnd(&stream);
    } catch (...) {
        inflateEnd(&stream);
       throw std::runtime_error("error in decompression");
    }

    return decompressedData;
}

size_t DpiEngine::findGzipHeaderOffset(const uint8_t* body, const size_t body_length)
{
    if (!body || body_length < 4) { // Need at least "\r\n1f8b" bytes to check
        throw std::invalid_argument("Body is null or too small to contain Gzip header");
    }

    // Iterate through the body to find "\r\n1f8b"
    for (size_t i = 0; i < body_length - 4; ++i) {
        if (body[i] == '\r' && body[i + 1] == '\n' &&
            body[i + 2] == 0x1f && body[i + 3] == 0x8b) {
            return i + 2; // Return the offset pointing to the Gzip header
            }
    }

    throw std::runtime_error("Gzip header not found in body");
}

pcpp::HttpRequestLayer* DpiEngine::parseHttpRequest(const std::string &http_message)
{
    // Try parsing as an HTTP request
    auto msg = const_cast<std::string&>(http_message);
    auto request_layer = new pcpp::HttpRequestLayer(
        reinterpret_cast<uint8_t*>(msg.data()),
        msg.size(),
        nullptr,
        nullptr);

    // Check if parsing succeeded
    if (request_layer->getFirstLine() != nullptr)
    {
        return request_layer;
    }

    return nullptr; // Parsing failed
}

pcpp::HttpResponseLayer* DpiEngine::parseHttpResponse(const std::string &http_message)
{
    // Try parsing as an HTTP response
    auto msg = const_cast<std::string&>(http_message);
    auto responseLayer = new pcpp::HttpResponseLayer(
        reinterpret_cast<uint8_t*>(msg.data()),
        msg.size(),
        nullptr,nullptr);

    // Check if parsing succeeded
    if (responseLayer->getFirstLine() != nullptr)
    {
        return responseLayer;
    }

    return nullptr; // Parsing failed
}

bool DpiEngine::isHttpMessageComplete(const std::string& http_frame)
{
    // Try parsing as an HTTP Response
    if (http_frame.compare(0,4,"HTTP") == 0)
    {
        auto http_response = parseHttpResponse(http_frame);
        if (http_response)
        {
            if (http_response->isHeaderComplete())
            {
                const pcpp::HeaderField* content_field = http_response->getFieldByName("Content-Length");
                if (content_field)
                {
                    size_t expected_body_size = std::stoi(content_field->getFieldValue());
                    size_t actual_body_size = http_response->getLayerPayloadSize();
                    return expected_body_size == actual_body_size;
                }

                const pcpp::HeaderField* encoding_field = http_response->getFieldByName("Transfer-Encoding");
                if (encoding_field && encoding_field->getFieldValue() == "chunked")
                {
                    // Check for terminating "\r\n0\r\n\r\n" chunk in the body
                    const uint8_t* body = http_response->getLayerPayload();
                    const size_t body_length = http_response->getLayerPayloadSize();
                    if (body_length >= 7 && std::string(reinterpret_cast<const char*>(body), body_length).substr(body_length - 7) == "\r\n0\r\n\r\n")
                    {
                        try {
                            // Extract the payload message from the http frame by Adjusting header length
                            const uint8_t* http_msg = reinterpret_cast<const uint8_t*>(http_frame.data()) + http_response->getHeaderLen();

                            // find the start of the gzip header offset
                            const size_t gzipOffset = findGzipHeaderOffset(http_msg, body_length);

                            // Adjust the http message to the gzip compress data
                            const uint8_t* gzip_msg = http_msg + gzipOffset;

                            //  decompress the gzip message (http message)
                            const std::string decompressedData = decompressGzip(gzip_msg, body_length - gzipOffset);
                            std::cout << "Decompressed Data: " << decompressedData << std::endl;
                        }catch (const std::exception& e) {
                            std::cerr << e.what() << std::endl;
                        }
                        return true;
                    }
                    std::cout << "=================chunked===================" << std::endl;
                    return false;
                }
                return true; // no body
            }
            return false; // Incomplete headers
        }
        std::cerr << "Not valid HTTP frame" << std::endl;
        return false;
    }
    auto http_request = parseHttpRequest(http_frame);
    if (http_request)
    {
        if (http_request->isHeaderComplete())
        {
            const pcpp::HeaderField* contentField = http_request->getFieldByName("Content-Length");
            if (contentField)
            {
                size_t expected_body_size = std::stoi(contentField->getFieldValue());
                size_t actual_body_size = http_request->getLayerPayloadSize();
                return expected_body_size == actual_body_size;
            }
            return true; // Headers complete, no body expected
        }
        return false; // Incomplete headers
    }
    std::cerr << "Not valid HTTP frame" << std::endl;
    return false;
}