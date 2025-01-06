#pragma once
#include <deque>
#include <TcpReassembly.h>
#include <HttpLayer.h>
#include <unordered_map>
#include<IPv4Layer.h>
#include <EthLayer.h>
#include <iostream>
#include <memory>
#include <zlib.h>
#include "Config.hpp"

class DpiEngine
{
private:
    const timeval TIMEVAL_ZERO = {0,0};
    pcpp::TcpReassembly _http_reassembly;
    std::unordered_map<uint32_t, std::string> _http_buffers;

    DpiEngine();
    static void tcpReassemblyMsgReadyCallback(const int8_t sideIndex, const pcpp::TcpStreamData& tcpData, void* userCookie);
    static std::string decompressGzip(const uint8_t *compress_data, size_t compress_size);
    bool isHttpMessageComplete(const std::string& http_frame) const;

public:
    ~DpiEngine() = default;
    DpiEngine(const DpiEngine&) = delete;
    const DpiEngine& operator=(const DpiEngine&) = delete;
    static DpiEngine& getInstance();


    void processDpiTcpPacket(pcpp::Packet& tcp_packet);
};