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

        try {
            auto result = dpi_engine->isHttpMessageComplete(http_frame);
            if (result)
            {
                auto& layerVariant = result.value();
                if (const auto* request_layer = std::get_if<std::unique_ptr<pcpp::HttpRequestLayer>>(&layerVariant))
                {
                    const auto& layer = *request_layer;
                    std::cout << "=================HTTP-Request=================" << layer.get()->toString() << std::endl;
                    std:: cout << http_frame << std::endl;
                }
                else if (const auto* response_layer = std::get_if<std::unique_ptr<pcpp::HttpResponseLayer>>(&layerVariant))
                {
                    const auto& layer = *response_layer;
                    std::cout << "=================HTTP-Response=================" << layer.get()->toString()<< std::endl;
                    std:: cout << http_frame << std::endl;
                }
                dpi_engine->_http_buffers.erase(session_key);
            }
        }catch (const std::exception& e) {
            std::cerr << e.what() << std::endl;
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
    if (!body || body_length < 2) { // Need at least "1f8b" bytes to check
        throw std::invalid_argument("Body is null or too small to contain Gzip header");
    }

    // Iterate through the body to find "1f8b"
    for (size_t i = 0; i < body_length - 2; ++i)
    {
        if (body[i] == 0x1f && body[i + 1] == 0x8b)
        {
            return i; // Return the offset pointing to the Gzip header
        }
    }
    throw std::runtime_error("Gzip header not found in body");
}

std::unique_ptr<pcpp::HttpRequestLayer> DpiEngine::createHttpRequestLayer(const std::string &http_message)
{
    uint8_t* rawBuffer = new uint8_t[http_message.size()]; //Pacpplusplus Layer own the rawBuffer and call delete[].
    std::memcpy(rawBuffer, http_message.data(), http_message.size()); // I must pass by copy to avoid two delete error

    return  std::make_unique<pcpp::HttpRequestLayer>(
        rawBuffer,
        http_message.size(),
        nullptr,
        nullptr);
}

std::unique_ptr<pcpp::HttpResponseLayer> DpiEngine::createHttpResponseLayer(const std::string &http_message)
{
    // Try parsing as an HTTP response
    uint8_t* rawBuffer = new uint8_t[http_message.size()]; // Pacpplusplus Layer own the rawBuffer and call delete[].
    std::memcpy(rawBuffer, http_message.data(), http_message.size()); // I must pass by copy to avoid two delete error

    return std::make_unique<pcpp::HttpResponseLayer>(
        rawBuffer,
        http_message.size(),
        nullptr,
        nullptr);
}

std::optional<DpiEngine::httpLayerVariant> DpiEngine::isHttpMessageComplete(const std::string& http_frame)
{
    if (http_frame.compare(0,1,"[") == 0)
    {
        return {};
    }
    // Try parsing as an HTTP Response
    if (http_frame.compare(0,4,"HTTP") == 0)
    {
        auto http_response = createHttpResponseLayer(http_frame);
        if (!http_response)
        {
            throw std::runtime_error("failed to create httpResponse layer");
        }
        if (!http_response->isHeaderComplete())
        {
            return httpLayerVariant{std::move(http_response)}; // Incomplete header
        }
        const pcpp::HeaderField* content_field = http_response->getFieldByName("Content-Length");
        if (content_field) //checking if the content-length field is equals to the http payload size
        {
            if(http_response->getContentLength() == http_response->getLayerPayloadSize()) {
                return {};
            }
            return httpLayerVariant{std::move(http_response)};
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
                return httpLayerVariant{std::move(http_response)};;
            }
            std::cout << "=================chunked===================" << std::endl;
            return {};
        }
        return httpLayerVariant{std::move(http_response)};; // no body
    }
    auto http_request = createHttpRequestLayer(http_frame);
    if (!http_request)
    {
        throw std::runtime_error("failed to create http request layer");
    }
    if (!http_request->isHeaderComplete())
    {
        return {}; // Incomplete header
    }
    const pcpp::HeaderField* contentField = http_request->getFieldByName("Content-Length");
    if (contentField)
    {
        const size_t expected_body_size = std::stoi(contentField->getFieldValue());
        if(expected_body_size == http_request->getLayerPayloadSize()) {
            return {};
        }
        return httpLayerVariant{std::move(http_request)};
    }
    return httpLayerVariant{std::move(http_request)}; // Headers complete, no payload expected
}