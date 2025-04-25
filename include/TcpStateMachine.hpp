#pragma once
#include "Packet.h"
#include "TcpLayer.h"
#include "TcpCommonTypes.hpp"
#include <memory>
#include "BlockedPacketException.hpp"

// Base State class
class TcpStateClass
{

public:
    virtual ~TcpStateClass() = default;

    virtual TCP_COMMON_TYPES::TcpState handleClientPacket(const pcpp::Packet& tcp_packet, const pcpp::tcphdr& tcp_header) = 0;

    virtual TCP_COMMON_TYPES::TcpState handleInternetPacket(const pcpp::Packet& tcp_packet, const pcpp::tcphdr& tcp_header) = 0;

    virtual TCP_COMMON_TYPES::TcpState getState() const = 0;
};

class UnknownState : public TcpStateClass
{
public:

    TCP_COMMON_TYPES::TcpState handleClientPacket(const pcpp::Packet& tcp_packet, const pcpp::tcphdr& tcp_header) override;

    TCP_COMMON_TYPES::TcpState handleInternetPacket(const pcpp::Packet& tcp_packet, const pcpp::tcphdr& tcp_header) override;

    TCP_COMMON_TYPES::TcpState getState() const override { return TCP_COMMON_TYPES::UNKNOWN; }
};

class SynSentState : public TcpStateClass
{
public:

    TCP_COMMON_TYPES::TcpState handleClientPacket(const pcpp::Packet& tcp_packet, const pcpp::tcphdr& tcp_header) override;

    TCP_COMMON_TYPES::TcpState handleInternetPacket(const pcpp::Packet& tcp_packet, const pcpp::tcphdr& tcp_header) override;

    TCP_COMMON_TYPES::TcpState getState() const override { return TCP_COMMON_TYPES::SYN_SENT; }
};

class SynReceivedState : public TcpStateClass
{
public:

    TCP_COMMON_TYPES::TcpState handleClientPacket(const pcpp::Packet& tcp_packet, const pcpp::tcphdr& tcp_header) override;

    TCP_COMMON_TYPES::TcpState handleInternetPacket(const pcpp::Packet& tcp_packet, const pcpp::tcphdr& tcp_header) override;

    TCP_COMMON_TYPES::TcpState getState() const override { return TCP_COMMON_TYPES::SYN_RECEIVED; }
};

class EstablishedState : public TcpStateClass
{

public:

    TCP_COMMON_TYPES::TcpState handleClientPacket(const pcpp::Packet& tcp_packet, const pcpp::tcphdr& tcp_header) override;

    TCP_COMMON_TYPES::TcpState handleInternetPacket(const pcpp::Packet& tcp_packet, const pcpp::tcphdr& tcp_header) override;

    TCP_COMMON_TYPES::TcpState getState() const override { return TCP_COMMON_TYPES::ESTABLISHED; }
};

class FinWait1State : public TcpStateClass
{
public:

    TCP_COMMON_TYPES::TcpState handleClientPacket(const pcpp::Packet& tcp_packet, const pcpp::tcphdr& tcp_header) override;

    TCP_COMMON_TYPES::TcpState handleInternetPacket(const pcpp::Packet& tcp_packet, const pcpp::tcphdr& tcp_header) override;

    TCP_COMMON_TYPES::TcpState getState() const override { return TCP_COMMON_TYPES::FIN_WAIT1; }
};

class FinWait2State : public TcpStateClass
{
public:

    TCP_COMMON_TYPES::TcpState handleClientPacket(const pcpp::Packet& tcp_packet, const pcpp::tcphdr& tcp_header) override;

    TCP_COMMON_TYPES::TcpState handleInternetPacket(const pcpp::Packet& tcp_packet, const pcpp::tcphdr& tcp_header) override;

    TCP_COMMON_TYPES::TcpState getState() const override { return TCP_COMMON_TYPES::FIN_WAIT2; }
};

class CloseWaitState : public TcpStateClass
{
public:

    TCP_COMMON_TYPES::TcpState handleClientPacket(const pcpp::Packet& tcp_packet, const pcpp::tcphdr& tcp_header) override;

    TCP_COMMON_TYPES::TcpState handleInternetPacket(const pcpp::Packet& tcp_packet, const pcpp::tcphdr& tcp_header) override;

    TCP_COMMON_TYPES::TcpState getState() const override { return TCP_COMMON_TYPES::CLOSE_WAIT; }
};

class LastAckState : public TcpStateClass
{
public:

    TCP_COMMON_TYPES::TcpState handleClientPacket(const pcpp::Packet& tcp_packet, const pcpp::tcphdr& tcp_header) override;

    TCP_COMMON_TYPES::TcpState handleInternetPacket(const pcpp::Packet& tcp_packet, const pcpp::tcphdr& tcp_header) override;

    TCP_COMMON_TYPES::TcpState getState() const override { return TCP_COMMON_TYPES::LAST_ACK; }
};

class TimeWaitState : public TcpStateClass
{
public:

    TCP_COMMON_TYPES::TcpState handleClientPacket(const pcpp::Packet& tcp_packet, const pcpp::tcphdr& tcp_header) override;

    TCP_COMMON_TYPES::TcpState handleInternetPacket(const pcpp::Packet& tcp_packet, const pcpp::tcphdr& tcp_header) override;

    TCP_COMMON_TYPES::TcpState getState() const override { return TCP_COMMON_TYPES::TIME_WAIT; }
};

// Factory for creating state objects
class TcpStateFactory
{
public:
    static std::unique_ptr<TcpStateClass> createState(TCP_COMMON_TYPES::TcpState state);
};