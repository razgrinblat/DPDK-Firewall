#include "DpiEngine.hpp"

DpiEngine::DpiEngine() : _http_reassembly(tcpReassemblyMsgReadyCallback,this),
_session_table(SessionTable::getInstance()), _http_rules_handler(HttpRulesHandler::getInstance())
{}

DpiEngine & DpiEngine::getInstance()
{
    static DpiEngine instance;
    return instance;
}

void DpiEngine::processHttpRequest(const std::unique_ptr<pcpp::HttpRequestLayer>& request_layer, const std::string& http_msg, const pcpp::ConnectionData& tcp_data)
{
    const auto& layer = *request_layer;
    if (!_http_rules_handler.allowOutboundForwarding(layer))
    {
        _session_table.blockSession(tcp_data.flowKey);
        std::cout << "session to Ip: " << tcp_data.dstIP << " is closed!" << std::endl;
    }
}

void DpiEngine::processHttpResponse(const std::unique_ptr<pcpp::HttpResponseLayer>& response_layer, const std::string& http_msg, const pcpp::ConnectionData& tcp_data)
{
    const auto& layer = *response_layer;
    if (!_http_rules_handler.allowInboundForwarding(layer))
    {
        _session_table.blockSession(tcp_data.flowKey);
        std::cout << "Session to Ip: " << tcp_data.dstIP << " is closed!" << std::endl;
    }
    else if (layer.getLayerPayloadSize() > 0)
    {
        if (const auto decompress_date =extractGzipContentFromResponse(layer))
        {
            std::cout << decompress_date.value() << std::endl;
            if (const auto word = _http_rules_handler.allowByPayloadForwarding(decompress_date.value()))
            {
                _session_table.blockSession(tcp_data.flowKey);
                std::cout << "Session to Ip: " << tcp_data.dstIP << " is closed! because the word: '" << word.value() << "' is in the html text" << std::endl;
            }
        }
        else if (!layer.getFieldByName(PCPP_HTTP_CONTENT_ENCODING_FIELD))
        {
            if (const auto word = _http_rules_handler.allowByPayloadForwarding(reinterpret_cast<const char*>(layer.getData())))
            {
                _session_table.blockSession(tcp_data.flowKey);
                std::cout << "Session to Ip: " <<tcp_data.dstIP << " is closed! because the word: " << word.value() << " is in the html text" << std::endl;
            }
        }
    }
}

void DpiEngine::processHttpMessage(const std::string &http_frame, const pcpp::ConnectionData &tcp_data)
{
    if (const auto result = isHttpMessageComplete(http_frame))
    {
        const auto& layer_variant = result.value();
        if (const auto* request_layer = std::get_if<std::unique_ptr<pcpp::HttpRequestLayer>>(&layer_variant))
        {
            processHttpRequest(*request_layer, http_frame, tcp_data);
        }
        else if (const auto* response_layer = std::get_if<std::unique_ptr<pcpp::HttpResponseLayer>>(&layer_variant))
        {
            processHttpResponse(*response_layer, http_frame, tcp_data);
        }
        _http_buffers.erase(tcp_data.flowKey);
    }
}

void DpiEngine::tcpReassemblyMsgReadyCallback(const int8_t sideIndex, const pcpp::TcpStreamData &tcpData,
                                              void *userCookie)
{
    if (tcpData.getConnectionData().dstPort == Config::HTTP_PORT && !tcpData.isBytesMissing())
    {
        DpiEngine* dpi_engine = static_cast<DpiEngine*>(userCookie);
        const uint32_t session_key  = tcpData.getConnectionData().flowKey;
        const size_t data_length = tcpData.getDataLength();
        const auto data = tcpData.getData();

        // Append reassembled data to the buffer
        std::string& http_frame = dpi_engine->_http_buffers[session_key];
        http_frame.append(reinterpret_cast<const char*>(data),data_length);

        try
        {
            dpi_engine->processHttpMessage(http_frame,tcpData.getConnectionData());
        }
        catch (const std::exception& e) {
            std::cerr << e.what() << std::endl;
        }
    }
}

void DpiEngine::processDpiTcpPacket(pcpp::Packet &tcp_packet)
{
    _http_reassembly.reassemblePacket(tcp_packet);
}

std::string DpiEngine::decompressGzip(const uint8_t* compress_data, const size_t compress_size)
{
    constexpr size_t buffer_size = 1024;
    char buffer[buffer_size];
    std::string decompressed_data;
    decompressed_data.reserve(compress_size);

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
            stream.avail_out = buffer_size; // Size of the output buffer

            int ret = inflate(&stream, Z_NO_FLUSH);

            if (ret != Z_OK && ret != Z_STREAM_END) {
                throw std::runtime_error("Decompression failed");
            }

            decompressed_data.append(buffer, buffer_size - stream.avail_out);

            if (ret == Z_STREAM_END) {
                break;
            }
        } while (stream.avail_out == 0);

        inflateEnd(&stream);
    } catch (...) {
        inflateEnd(&stream);
       throw std::runtime_error("error in decompression");
    }

    return decompressed_data;
}

size_t DpiEngine::findGzipHeaderOffset(const uint8_t* body, const size_t body_length)
{
    if (!body || body_length < 2) { // Need at least "1f8b" bytes to check
        throw std::invalid_argument("Body is null or too small to contain Gzip header");
    }

    // Iterate through the body to find "1f8b" - start of gzip header
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
    uint8_t* rawBuffer = new uint8_t[http_message.size()]; //Pcapplusplus Layer class own the rawBuffer and call delete[].
    std::memcpy(rawBuffer, http_message.data(), http_message.size()); // I must pass by copy to avoid two deletion error

    auto layer = std::make_unique<pcpp::HttpRequestLayer>(
        rawBuffer,
        http_message.size(),
        nullptr,
        nullptr);

    if (!layer) throw std::runtime_error("Invalid HTTP request Layer");
    return layer;
}

std::unique_ptr<pcpp::HttpResponseLayer> DpiEngine::createHttpResponseLayer(const std::string &http_message)
{
    uint8_t* rawBuffer = new uint8_t[http_message.size()]; // Pcappplusplus Layer class own the rawBuffer and call delete[].
    std::memcpy(rawBuffer, http_message.data(), http_message.size()); // I must pass by copy to avoid two deletion error

    auto layer =  std::make_unique<pcpp::HttpResponseLayer>(
        rawBuffer,
        http_message.size(),
        nullptr,
        nullptr);

    if (!layer) throw std::runtime_error("Invalid HTTP response Layer");
    return layer;
}

std::optional<std::string> DpiEngine::extractGzipContentFromResponse(const pcpp::HttpResponseLayer &response_layer)
{
    const pcpp::HeaderField* content_type = response_layer.getFieldByName(PCPP_HTTP_CONTENT_TYPE_FIELD);
    const pcpp::HeaderField* content_encoding = response_layer.getFieldByName(PCPP_HTTP_CONTENT_ENCODING_FIELD);
    if (content_type && content_encoding && content_type->getFieldValue() == "text/html"
        && content_encoding->getFieldValue() == "gzip")
    {
        const size_t body_length = response_layer.getLayerPayloadSize();
        // Extract the payload message from the http layer
        const uint8_t* http_msg = response_layer.getLayerPayload();

        // find the start of the gzip header offset
        const size_t gzipOffset = findGzipHeaderOffset(http_msg, body_length);

        // Adjust the http message to the gzip compress data
        const uint8_t* gzip_msg = http_msg + gzipOffset;

        //  decompress the gzip message (http message)
        return {decompressGzip(gzip_msg, body_length - gzipOffset)};
    }
    return {};
}

bool DpiEngine::hasChunkedTerminator(const uint8_t *body, const size_t length)
{
    if (length < http_chunked_tail.size()) return false;

    const std::string_view body_view(reinterpret_cast<const char*>(body), length);
    return body_view.substr(length - http_chunked_tail.size()) == http_chunked_tail;
}

bool DpiEngine::isContentLengthComplete(const pcpp::HeaderField *field, const size_t actualPayloadSize)
{
    try
    {
        const size_t expected = std::stoul(field->getFieldValue());
        return expected == actualPayloadSize;
    }
    catch (...)
    {
        return false;
    }
}

std::optional<DpiEngine::httpLayerVariant> DpiEngine::handleHttpResponse(const std::string &http_frame)
{
    auto http_response = createHttpResponseLayer(http_frame);

    const auto* content_field = http_response->getFieldByName(PCPP_HTTP_CONTENT_LENGTH_FIELD);
    if (content_field)
    {
        if (!isContentLengthComplete(content_field, http_response->getLayerPayloadSize()))
            return {};
        return httpLayerVariant{std::move(http_response)};
    }

    const auto* encoding_field = http_response->getFieldByName(PCPP_HTTP_TRANSFER_ENCODING_FIELD);
    if (encoding_field && encoding_field->getFieldValue() == "chunked")
    {
        if (hasChunkedTerminator(http_response->getLayerPayload(), http_response->getLayerPayloadSize()))
            return httpLayerVariant{std::move(http_response)};
        return {};
    }

    return httpLayerVariant{std::move(http_response)};
}

std::optional<DpiEngine::httpLayerVariant> DpiEngine::handleHttpRequest(const std::string &http_frame)
{
    auto http_request = createHttpRequestLayer(http_frame);

    const auto* content_field = http_request->getFieldByName(PCPP_HTTP_CONTENT_LENGTH_FIELD);
    if (content_field)
    {
        if (!isContentLengthComplete(content_field, http_request->getLayerPayloadSize()))
            return {};
        return httpLayerVariant{std::move(http_request)};
    }

    return httpLayerVariant{std::move(http_request)};
}

std::optional<DpiEngine::httpLayerVariant> DpiEngine::isHttpMessageComplete(const std::string& http_frame)
{
    if (http_frame.rfind("HTTP", 0) == 0)
        return handleHttpResponse(http_frame);
    else
        return handleHttpRequest(http_frame);
}