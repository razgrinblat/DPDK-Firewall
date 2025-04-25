#include "TcpStateMachine.hpp"

std::unique_ptr<TcpStateClass> TcpStateFactory::createState(const TCP_COMMON_TYPES::TcpState state)
{
    switch (state)
    {
        case TCP_COMMON_TYPES::SYN_SENT:
            return std::make_unique<SynSentState>();
        case TCP_COMMON_TYPES::SYN_RECEIVED:
            return std::make_unique<SynReceivedState>();
        case TCP_COMMON_TYPES::ESTABLISHED:
            return std::make_unique<EstablishedState>();
        case TCP_COMMON_TYPES::FIN_WAIT1:
            return std::make_unique<FinWait1State>();
        case TCP_COMMON_TYPES::FIN_WAIT2:
            return std::make_unique<FinWait2State>();
        case TCP_COMMON_TYPES::CLOSE_WAIT:
            return std::make_unique<CloseWaitState>();
        case TCP_COMMON_TYPES::LAST_ACK:
            return std::make_unique<LastAckState>();
        case TCP_COMMON_TYPES::TIME_WAIT:
            return std::make_unique<TimeWaitState>();
        case TCP_COMMON_TYPES::UNKNOWN:
        default:
            return std::make_unique<UnknownState>();
    }
}

// SynSentState implementation
TCP_COMMON_TYPES::TcpState SynSentState::handleClientPacket(const pcpp::Packet& tcp_packet, const pcpp::tcphdr& tcp_header)
{
    if (tcp_header.synFlag) {
        // SYN retransmission
        return TCP_COMMON_TYPES::SYN_SENT;
    }
    else {
        throw BlockedPacket("Invalid client packet in SYN_SENT state\nPacket Details:\n " + tcp_packet.toString());
    }
}

TCP_COMMON_TYPES::TcpState SynSentState::handleInternetPacket(const pcpp::Packet& tcp_packet, const pcpp::tcphdr& tcp_header)
{
    if (tcp_header.synFlag && tcp_header.ackFlag) {
        return TCP_COMMON_TYPES::SYN_RECEIVED;
    }

    throw BlockedPacket("Invalid internet packet in SYN_SENT state\nPacket Details:\n " + tcp_packet.toString());
}

// SynReceivedState implementation
TCP_COMMON_TYPES::TcpState SynReceivedState::handleClientPacket(const pcpp::Packet& tcp_packet, const pcpp::tcphdr& tcp_header)
{
    if (tcp_header.ackFlag && !tcp_header.finFlag)
    {
        return TCP_COMMON_TYPES::ESTABLISHED;
    }
    throw BlockedPacket("Invalid client packet in SYN_RECEIVED state\nPacket Details:\n " + tcp_packet.toString());
}

TCP_COMMON_TYPES::TcpState SynReceivedState::handleInternetPacket(const pcpp::Packet& tcp_packet, const pcpp::tcphdr& tcp_header)
{
    if (tcp_header.synFlag && tcp_header.ackFlag)
    {
        // Retransmission
        return TCP_COMMON_TYPES::SYN_RECEIVED;
    }
    throw BlockedPacket("Invalid internet packet in SYN_RECEIVED state\nPacket Details:\n " + tcp_packet.toString());
}

// EstablishedState implementation
TCP_COMMON_TYPES::TcpState EstablishedState::handleClientPacket(const pcpp::Packet& tcp_packet, const pcpp::tcphdr& tcp_header)
{
    if (tcp_header.ackFlag && !tcp_header.finFlag)
    {
        return TCP_COMMON_TYPES::ESTABLISHED;
    }
    if (tcp_header.finFlag)
    {
        // Active close from client
        return TCP_COMMON_TYPES::FIN_WAIT1;
    }
    throw BlockedPacket("Invalid client packet in ESTABLISHED state\nPacket Details:\n " + tcp_packet.toString());
}

TCP_COMMON_TYPES::TcpState EstablishedState::handleInternetPacket(const pcpp::Packet& tcp_packet, const pcpp::tcphdr& tcp_header)
{
    if (tcp_header.ackFlag && !tcp_header.finFlag)
    {
        return TCP_COMMON_TYPES::ESTABLISHED;
    }
    if (tcp_header.finFlag) {
        // Active close from internet
        return TCP_COMMON_TYPES::CLOSE_WAIT;
    }
    throw BlockedPacket("Invalid internet packet in ESTABLISHED state\nPacket Details:\n " + tcp_packet.toString());
}

// FinWait1State implementation
TCP_COMMON_TYPES::TcpState FinWait1State::handleClientPacket(const pcpp::Packet& tcp_packet, const pcpp::tcphdr& tcp_header)
{
    if (tcp_header.finFlag) {
        // FIN retransmission
       return TCP_COMMON_TYPES::FIN_WAIT1;
    }
    if (tcp_header.ackFlag)
    {
        return TCP_COMMON_TYPES::FIN_WAIT1;
    }
    throw BlockedPacket("Invalid client packet in FIN_WAIT1 state\nPacket Details:\n " + tcp_packet.toString());
}

TCP_COMMON_TYPES::TcpState FinWait1State::handleInternetPacket(const pcpp::Packet& tcp_packet, const pcpp::tcphdr& tcp_header)
{
    if (tcp_header.ackFlag && !tcp_header.finFlag) {
        return TCP_COMMON_TYPES::FIN_WAIT2;
    }
    if (tcp_header.finFlag && tcp_header.ackFlag) {
        return TCP_COMMON_TYPES::TIME_WAIT;
    }
    throw BlockedPacket("Invalid internet packet in FIN_WAIT1 state\nPacket Details:\n " + tcp_packet.toString());
}

// FinWait2State implementation
TCP_COMMON_TYPES::TcpState FinWait2State::handleClientPacket(const pcpp::Packet& tcp_packet, const pcpp::tcphdr& tcp_header)
{
    if (tcp_header.ackFlag)
    {
        return TCP_COMMON_TYPES::FIN_WAIT2;
    }
    throw BlockedPacket("Invalid client packet in FIN_WAIT2 state\nPacket Details:\n " + tcp_packet.toString());
}

TCP_COMMON_TYPES::TcpState FinWait2State::handleInternetPacket(const pcpp::Packet& tcp_packet, const pcpp::tcphdr& tcp_header)
{
    if (tcp_header.ackFlag && !tcp_header.finFlag) {
        // Delayed data transfer
        return  TCP_COMMON_TYPES::FIN_WAIT2;
    }
    if (tcp_header.finFlag) {
        return TCP_COMMON_TYPES::TIME_WAIT;
    }
    throw BlockedPacket("Invalid internet packet in FIN_WAIT2 state\nPacket Details:\n " + tcp_packet.toString());
}

// CloseWaitState implementation
TCP_COMMON_TYPES::TcpState CloseWaitState::handleClientPacket(const pcpp::Packet& tcp_packet, const pcpp::tcphdr& tcp_header)
{
    if (tcp_header.ackFlag && !tcp_header.finFlag)
    {
        return TCP_COMMON_TYPES::CLOSE_WAIT;
    }
    if (tcp_header.finFlag)
    {
        return TCP_COMMON_TYPES::LAST_ACK;
    }
    throw BlockedPacket("Invalid client packet in CLOSE_WAIT state\nPacket Details:\n " + tcp_packet.toString());
}

TCP_COMMON_TYPES::TcpState CloseWaitState::handleInternetPacket(const pcpp::Packet& tcp_packet, const pcpp::tcphdr& tcp_header)
{
    if (tcp_header.finFlag)
    {
        // FIN retransmissions
        return TCP_COMMON_TYPES::CLOSE_WAIT;
    }
    if (tcp_header.ackFlag)
    {
        // Delayed data transfer
        return TCP_COMMON_TYPES::CLOSE_WAIT;
    }
    throw BlockedPacket("Invalid internet packet in CLOSE_WAIT state\nPacket Details:\n " + tcp_packet.toString());
}

// LastAckState implementation
TCP_COMMON_TYPES::TcpState LastAckState::handleClientPacket(const pcpp::Packet& tcp_packet, const pcpp::tcphdr& tcp_header)
{
    if (tcp_header.finFlag || tcp_header.ackFlag) {
        // FIN retransmissions
        return TCP_COMMON_TYPES::LAST_ACK;
    }
    throw BlockedPacket("Invalid client packet in LAST_ACK state\nPacket Details:\n " + tcp_packet.toString());
}

TCP_COMMON_TYPES::TcpState LastAckState::handleInternetPacket(const pcpp::Packet& tcp_packet, const pcpp::tcphdr& tcp_header)
{
    if (tcp_header.ackFlag) {
        return TCP_COMMON_TYPES::TIME_WAIT;
    }
    throw BlockedPacket("Invalid internet packet in LAST_ACK state\nPacket Details:\n " + tcp_packet.toString());
}

// TimeWaitState implementation
TCP_COMMON_TYPES::TcpState TimeWaitState::handleClientPacket(const pcpp::Packet& tcp_packet, const pcpp::tcphdr& tcp_header)
{
    if (tcp_header.ackFlag) {
        // Duplicate ACKs due to bad connection
        return TCP_COMMON_TYPES::TIME_WAIT;
    }
    throw BlockedPacket("Invalid client packet in TIME_WAIT state\nPacket Details:\n " + tcp_packet.toString());
}

TCP_COMMON_TYPES::TcpState TimeWaitState::handleInternetPacket(const pcpp::Packet& tcp_packet, const pcpp::tcphdr& tcp_header)
{
    if (tcp_header.ackFlag || tcp_header.finFlag)
    {
        // Duplicate ACKs or FINs due to bad connection
        return TCP_COMMON_TYPES::TIME_WAIT;
    }
    throw BlockedPacket("Invalid internet packet in TIME_WAIT state\nPacket Details:\n " + tcp_packet.toString());
}

// UnknownState implementation (fallback)
TCP_COMMON_TYPES::TcpState UnknownState::handleClientPacket(const pcpp::Packet& tcp_packet, const pcpp::tcphdr& tcp_header)
{
    throw BlockedPacket("Cannot process packet in UNKNOWN state\nPacket Details:\n " + tcp_packet.toString());
}

TCP_COMMON_TYPES::TcpState UnknownState::handleInternetPacket(const pcpp::Packet& tcp_packet, const pcpp::tcphdr& tcp_header)
{
    throw BlockedPacket("Cannot process packet in UNKNOWN state\nPacket Details:\n " + tcp_packet.toString());
}