#include "TcpStateMachine.hpp"
#include "TcpSessionHandler.hpp"

std::unique_ptr<TcpStateClass> TcpStateFactory::createState(const SessionTable::TcpState state, TcpSessionHandler* context) {
    switch (state)
    {
        case TCP_COMMON_TYPES::SYN_SENT:
            return std::make_unique<SynSentState>(context);
        case TCP_COMMON_TYPES::SYN_RECEIVED:
            return std::make_unique<SynReceivedState>(context);
        case TCP_COMMON_TYPES::ESTABLISHED:
            return std::make_unique<EstablishedState>(context);
        case TCP_COMMON_TYPES::FIN_WAIT1:
            return std::make_unique<FinWait1State>(context);
        case TCP_COMMON_TYPES::FIN_WAIT2:
            return std::make_unique<FinWait2State>(context);
        case TCP_COMMON_TYPES::CLOSE_WAIT:
            return std::make_unique<CloseWaitState>(context);
        case TCP_COMMON_TYPES::LAST_ACK:
            return std::make_unique<LastAckState>(context);
        case TCP_COMMON_TYPES::TIME_WAIT:
            return std::make_unique<TimeWaitState>(context);
        case TCP_COMMON_TYPES::UNKNOWN:
        default:
            return std::make_unique<UnknownState>(context);
    }
}

// SynSentState implementation
TCP_COMMON_TYPES::TcpState SynSentState::handleClientPacket(pcpp::Packet& tcp_packet, const uint32_t tcp_hash,
                                     const pcpp::tcphdr& tcp_header, const uint32_t packet_size)
{
    if (tcp_header.synFlag) {
        // SYN retransmission
        return TCP_COMMON_TYPES::SYN_SENT;
    }
    else {
        throw std::runtime_error("Invalid client packet in SYN_SENT state: " + tcp_packet.toString());
    }
}

TCP_COMMON_TYPES::TcpState SynSentState::handleInternetPacket(pcpp::Packet& tcp_packet, const uint32_t tcp_hash,
                                       const pcpp::tcphdr& tcp_header, const uint32_t packet_size)
{
    if (tcp_header.synFlag && tcp_header.ackFlag) {
        return TCP_COMMON_TYPES::SYN_RECEIVED;
    }
    else {
        throw std::runtime_error("Invalid internet packet in SYN_SENT state: " + tcp_packet.toString());
    }
}

// SynReceivedState implementation
TCP_COMMON_TYPES::TcpState SynReceivedState::handleClientPacket(pcpp::Packet& tcp_packet, const uint32_t tcp_hash,
                                         const pcpp::tcphdr& tcp_header, const uint32_t packet_size)
{
    if (tcp_header.ackFlag && !tcp_header.finFlag)
    {
        return TCP_COMMON_TYPES::ESTABLISHED;
    }
    else {
        throw std::runtime_error("Invalid client packet in SYN_RECEIVED state: " + tcp_packet.toString());
    }
}

TCP_COMMON_TYPES::TcpState SynReceivedState::handleInternetPacket(pcpp::Packet& tcp_packet, const uint32_t tcp_hash,
                                           const pcpp::tcphdr& tcp_header, const uint32_t packet_size)
{
    if (tcp_header.synFlag && tcp_header.ackFlag)
    {
        // Retransmission
        return TCP_COMMON_TYPES::SYN_RECEIVED;
    }
    throw std::runtime_error("Invalid internet packet in SYN_RECEIVED state: " + tcp_packet.toString());
}

// EstablishedState implementation
TCP_COMMON_TYPES::TcpState EstablishedState::handleClientPacket(pcpp::Packet& tcp_packet, const uint32_t tcp_hash,
                                         const pcpp::tcphdr& tcp_header, const uint32_t packet_size)
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
    throw std::runtime_error("Invalid client packet in ESTABLISHED state: " + tcp_packet.toString());
}

TCP_COMMON_TYPES::TcpState EstablishedState::handleInternetPacket(pcpp::Packet& tcp_packet, const uint32_t tcp_hash,
                                           const pcpp::tcphdr& tcp_header, const uint32_t packet_size)
{
    if (tcp_header.ackFlag && !tcp_header.finFlag)
    {
        return TCP_COMMON_TYPES::ESTABLISHED;
    }
    if (tcp_header.finFlag) {
        // Active close from internet
        return TCP_COMMON_TYPES::CLOSE_WAIT;
    }
    throw std::runtime_error("Invalid internet packet in ESTABLISHED state: " + tcp_packet.toString());
}

// FinWait1State implementation
TCP_COMMON_TYPES::TcpState FinWait1State::handleClientPacket(pcpp::Packet& tcp_packet, const uint32_t tcp_hash,
                                      const pcpp::tcphdr& tcp_header, const uint32_t packet_size)
{
    if (tcp_header.finFlag) {
        // FIN retransmission
       return TCP_COMMON_TYPES::FIN_WAIT1;
    }
    if (tcp_header.ackFlag)
    {
        return TCP_COMMON_TYPES::FIN_WAIT1;
    }
    throw std::runtime_error("Invalid client packet in FIN_WAIT1 state: " + tcp_packet.toString());
}

TCP_COMMON_TYPES::TcpState FinWait1State::handleInternetPacket(pcpp::Packet& tcp_packet, const uint32_t tcp_hash,
                                        const pcpp::tcphdr& tcp_header, const uint32_t packet_size)
{
    if (tcp_header.ackFlag && !tcp_header.finFlag) {
        return TCP_COMMON_TYPES::FIN_WAIT2;
    }
    if (tcp_header.finFlag && tcp_header.ackFlag) {
        return TCP_COMMON_TYPES::TIME_WAIT;
    }
    throw std::runtime_error("Invalid internet packet in FIN_WAIT1 state: " + tcp_packet.toString());
}

// FinWait2State implementation
TCP_COMMON_TYPES::TcpState FinWait2State::handleClientPacket(pcpp::Packet& tcp_packet, const uint32_t tcp_hash,
                                      const pcpp::tcphdr& tcp_header, const uint32_t packet_size)
{
    if (tcp_header.ackFlag)
    {
        return TCP_COMMON_TYPES::FIN_WAIT2;
    }
    throw std::runtime_error("Invalid client packet in FIN_WAIT2 state: " + tcp_packet.toString());
}

TCP_COMMON_TYPES::TcpState FinWait2State::handleInternetPacket(pcpp::Packet& tcp_packet, const uint32_t tcp_hash,
                                        const pcpp::tcphdr& tcp_header, const uint32_t packet_size)
{
    if (tcp_header.ackFlag && !tcp_header.finFlag) {
        // Delayed data transfer
        return  TCP_COMMON_TYPES::FIN_WAIT2;
    }
    if (tcp_header.finFlag) {
        return TCP_COMMON_TYPES::TIME_WAIT;
    }
    throw std::runtime_error("Invalid internet packet in FIN_WAIT2 state: " + tcp_packet.toString());
}

// CloseWaitState implementation
TCP_COMMON_TYPES::TcpState CloseWaitState::handleClientPacket(pcpp::Packet& tcp_packet, const uint32_t tcp_hash,
                                       const pcpp::tcphdr& tcp_header, const uint32_t packet_size)
{
    if (tcp_header.ackFlag && !tcp_header.finFlag)
    {
        return TCP_COMMON_TYPES::CLOSE_WAIT;
    }
    if (tcp_header.finFlag)
    {
        return TCP_COMMON_TYPES::LAST_ACK;
    }
    throw std::runtime_error("Invalid client packet in CLOSE_WAIT state: " + tcp_packet.toString());
}

TCP_COMMON_TYPES::TcpState CloseWaitState::handleInternetPacket(pcpp::Packet& tcp_packet, const uint32_t tcp_hash,
                                         const pcpp::tcphdr& tcp_header, const uint32_t packet_size)
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
    throw std::runtime_error("Invalid internet packet in CLOSE_WAIT state: " + tcp_packet.toString());
}

// LastAckState implementation
TCP_COMMON_TYPES::TcpState LastAckState::handleClientPacket(pcpp::Packet& tcp_packet, const uint32_t tcp_hash,
                                     const pcpp::tcphdr& tcp_header, const uint32_t packet_size)
{
    if (tcp_header.finFlag) {
        // FIN retransmissions
        return TCP_COMMON_TYPES::LAST_ACK;
    }
    throw std::runtime_error("Invalid client packet in LAST_ACK state: " + tcp_packet.toString());
}

TCP_COMMON_TYPES::TcpState LastAckState::handleInternetPacket(pcpp::Packet& tcp_packet, const uint32_t tcp_hash,
                                       const pcpp::tcphdr& tcp_header, const uint32_t packet_size)
{
    if (tcp_header.ackFlag) {
        return TCP_COMMON_TYPES::TIME_WAIT;
    }
    throw std::runtime_error("Invalid internet packet in LAST_ACK state: " + tcp_packet.toString());
}

// TimeWaitState implementation
TCP_COMMON_TYPES::TcpState TimeWaitState::handleClientPacket(pcpp::Packet& tcp_packet, const uint32_t tcp_hash,
                                      const pcpp::tcphdr& tcp_header, const uint32_t packet_size)
{
    if (tcp_header.ackFlag) {
        // Duplicate ACKs due to bad connection
        return TCP_COMMON_TYPES::TIME_WAIT;
    }
    throw std::runtime_error("Invalid client packet in TIME_WAIT state: " + tcp_packet.toString());
}

TCP_COMMON_TYPES::TcpState TimeWaitState::handleInternetPacket(pcpp::Packet& tcp_packet, const uint32_t tcp_hash,
                                        const pcpp::tcphdr& tcp_header, const uint32_t packet_size)
{
    if (tcp_header.ackFlag || tcp_header.finFlag)
    {
        // Duplicate ACKs or FINs due to bad connection
        return TCP_COMMON_TYPES::TIME_WAIT;
    }
    throw std::runtime_error("Invalid internet packet in TIME_WAIT state: " + tcp_packet.toString());
}

// UnknownState implementation (fallback)
TCP_COMMON_TYPES::TcpState UnknownState::handleClientPacket(pcpp::Packet& tcp_packet, uint32_t tcp_hash,
                                     const pcpp::tcphdr& tcp_header, uint32_t packet_size)
{
    throw std::runtime_error("Cannot process packet in UNKNOWN state: " + tcp_packet.toString());
}

TCP_COMMON_TYPES::TcpState UnknownState::handleInternetPacket(pcpp::Packet& tcp_packet, uint32_t tcp_hash,
                                       const pcpp::tcphdr& tcp_header, uint32_t packet_size)
{
    throw std::runtime_error("Cannot process packet in UNKNOWN state: " + tcp_packet.toString());
}