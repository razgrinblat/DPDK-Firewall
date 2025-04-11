#pragma once
#include "Packet.h"
#include "TcpLayer.h"
#include "TcpCommonTypes.hpp"
#include <memory>

class DpiEngine;
class TcpSessionHandler;

// Base State class
class TcpStateClass
{
protected:
    TcpSessionHandler* _context;

public:
    TcpStateClass(TcpSessionHandler* context) : _context(context) {}
    virtual ~TcpStateClass() = default;

    virtual void handleClientPacket(pcpp::Packet& tcp_packet, uint32_t tcp_hash,
                                   const pcpp::tcphdr& tcp_header, uint32_t packet_size) = 0;

    virtual void handleInternetPacket(pcpp::Packet& tcp_packet, uint32_t tcp_hash,
                                     const pcpp::tcphdr& tcp_header, uint32_t packet_size) = 0;

    virtual TCP_COMMON_TYPES::TcpState getState() const = 0;
};

class UnknownState : public TcpStateClass
{
public:
    UnknownState(TcpSessionHandler* context) : TcpStateClass(context) {}

    void handleClientPacket(pcpp::Packet& tcp_packet, uint32_t tcp_hash,
                           const pcpp::tcphdr& tcp_header, uint32_t packet_size) override;

    void handleInternetPacket(pcpp::Packet& tcp_packet, uint32_t tcp_hash,
                             const pcpp::tcphdr& tcp_header, uint32_t packet_size) override;

    TCP_COMMON_TYPES::TcpState getState() const override { return TCP_COMMON_TYPES::UNKNOWN; }
};

class SynSentState : public TcpStateClass
{
public:
    SynSentState(TcpSessionHandler* context) : TcpStateClass(context) {}

    void handleClientPacket(pcpp::Packet& tcp_packet, uint32_t tcp_hash,
                           const pcpp::tcphdr& tcp_header, uint32_t packet_size) override;

    void handleInternetPacket(pcpp::Packet& tcp_packet, uint32_t tcp_hash,
                             const pcpp::tcphdr& tcp_header, uint32_t packet_size) override;

    TCP_COMMON_TYPES::TcpState getState() const override { return TCP_COMMON_TYPES::SYN_SENT; }
};

class SynReceivedState : public TcpStateClass
{
public:
    SynReceivedState(TcpSessionHandler* context) : TcpStateClass(context) {}

    void handleClientPacket(pcpp::Packet& tcp_packet, uint32_t tcp_hash,
                           const pcpp::tcphdr& tcp_header, uint32_t packet_size) override;

    void handleInternetPacket(pcpp::Packet& tcp_packet, uint32_t tcp_hash,
                             const pcpp::tcphdr& tcp_header, uint32_t packet_size) override;

    TCP_COMMON_TYPES::TcpState getState() const override { return TCP_COMMON_TYPES::SYN_RECEIVED; }
};

class EstablishedState : public TcpStateClass
{

public:
    EstablishedState(TcpSessionHandler* context) : TcpStateClass(context){}

    void handleClientPacket(pcpp::Packet& tcp_packet, uint32_t tcp_hash,
                            const pcpp::tcphdr& tcp_header, uint32_t packet_size) override;

    void handleInternetPacket(pcpp::Packet& tcp_packet, uint32_t tcp_hash,
                             const pcpp::tcphdr& tcp_header, uint32_t packet_size) override;

    TCP_COMMON_TYPES::TcpState getState() const override { return TCP_COMMON_TYPES::ESTABLISHED; }
};

class FinWait1State : public TcpStateClass
{
public:
    FinWait1State(TcpSessionHandler* context) : TcpStateClass(context) {}

    void handleClientPacket(pcpp::Packet& tcp_packet, uint32_t tcp_hash,
                           const pcpp::tcphdr& tcp_header, uint32_t packet_size) override;

    void handleInternetPacket(pcpp::Packet& tcp_packet, uint32_t tcp_hash,
                             const pcpp::tcphdr& tcp_header, uint32_t packet_size) override;

    TCP_COMMON_TYPES::TcpState getState() const override { return TCP_COMMON_TYPES::FIN_WAIT1; }
};

class FinWait2State : public TcpStateClass
{
public:
    FinWait2State(TcpSessionHandler* context) : TcpStateClass(context) {}

    void handleClientPacket(pcpp::Packet& tcp_packet, uint32_t tcp_hash,
                           const pcpp::tcphdr& tcp_header, uint32_t packet_size) override;

    void handleInternetPacket(pcpp::Packet& tcp_packet, uint32_t tcp_hash,
                             const pcpp::tcphdr& tcp_header, uint32_t packet_size) override;

    TCP_COMMON_TYPES::TcpState getState() const override { return TCP_COMMON_TYPES::FIN_WAIT2; }
};

class CloseWaitState : public TcpStateClass
{
public:
    CloseWaitState(TcpSessionHandler* context) : TcpStateClass(context) {}

    void handleClientPacket(pcpp::Packet& tcp_packet, uint32_t tcp_hash,
                           const pcpp::tcphdr& tcp_header, uint32_t packet_size) override;

    void handleInternetPacket(pcpp::Packet& tcp_packet, uint32_t tcp_hash,
                             const pcpp::tcphdr& tcp_header, uint32_t packet_size) override;

    TCP_COMMON_TYPES::TcpState getState() const override { return TCP_COMMON_TYPES::CLOSE_WAIT; }
};

class LastAckState : public TcpStateClass
{
public:
    LastAckState(TcpSessionHandler* context) : TcpStateClass(context) {}

    void handleClientPacket(pcpp::Packet& tcp_packet, uint32_t tcp_hash,
                           const pcpp::tcphdr& tcp_header, uint32_t packet_size) override;

    void handleInternetPacket(pcpp::Packet& tcp_packet, uint32_t tcp_hash,
                             const pcpp::tcphdr& tcp_header, uint32_t packet_size) override;

    TCP_COMMON_TYPES::TcpState getState() const override { return TCP_COMMON_TYPES::LAST_ACK; }
};

class TimeWaitState : public TcpStateClass
{
public:
    TimeWaitState(TcpSessionHandler* context) : TcpStateClass(context) {}

    void handleClientPacket(pcpp::Packet& tcp_packet, uint32_t tcp_hash,
                           const pcpp::tcphdr& tcp_header, uint32_t packet_size) override;

    void handleInternetPacket(pcpp::Packet& tcp_packet, uint32_t tcp_hash,
                             const pcpp::tcphdr& tcp_header, uint32_t packet_size) override;

    TCP_COMMON_TYPES::TcpState getState() const override { return TCP_COMMON_TYPES::TIME_WAIT; }
};

// Factory for creating state objects
class TcpStateFactory
{
public:
    static std::unique_ptr<TcpStateClass> createState(TCP_COMMON_TYPES::TcpState state, TcpSessionHandler* context);
};