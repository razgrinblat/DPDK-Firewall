#include "TcpStateMachine.hpp"
#include "TcpSessionHandler.hpp"
#include "SessionTable.hpp"

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
void SynSentState::handleClientPacket(pcpp::Packet& tcp_packet, const uint32_t tcp_hash,
                                     const pcpp::tcphdr& tcp_header, const uint32_t packet_size)
{
    if (tcp_header.synFlag) {
        // SYN retransmission
        _context->updateSession(tcp_hash, TCP_COMMON_TYPES::SYN_SENT, packet_size, true);
    }
    else {
        throw std::runtime_error("Invalid client packet in SYN_SENT state: " + tcp_packet.toString());
    }
}

void SynSentState::handleInternetPacket(pcpp::Packet& tcp_packet, const uint32_t tcp_hash,
                                       const pcpp::tcphdr& tcp_header, const uint32_t packet_size)
{
    if (tcp_header.synFlag && tcp_header.ackFlag) {
        _context->updateSession(tcp_hash, TCP_COMMON_TYPES::SYN_RECEIVED, packet_size, false);
    }
    else {
        throw std::runtime_error("Invalid internet packet in SYN_SENT state: " + tcp_packet.toString());
    }
}

// SynReceivedState implementation
void SynReceivedState::handleClientPacket(pcpp::Packet& tcp_packet, const uint32_t tcp_hash,
                                         const pcpp::tcphdr& tcp_header, const uint32_t packet_size)
{
    if (tcp_header.ackFlag && !tcp_header.finFlag)
    {
        _context->updateSession(tcp_hash, TCP_COMMON_TYPES::ESTABLISHED, packet_size, true);
    }
    else {
        throw std::runtime_error("Invalid client packet in SYN_RECEIVED state: " + tcp_packet.toString());
    }
}

void SynReceivedState::handleInternetPacket(pcpp::Packet& tcp_packet, const uint32_t tcp_hash,
                                           const pcpp::tcphdr& tcp_header, const uint32_t packet_size)
{
    if (tcp_header.synFlag && tcp_header.ackFlag)
    {
        // Retransmission
        _context->updateSession(tcp_hash, TCP_COMMON_TYPES::SYN_RECEIVED, packet_size, false);
    }
    else {
        throw std::runtime_error("Invalid internet packet in SYN_RECEIVED state: " + tcp_packet.toString());
    }
}

// EstablishedState implementation
void EstablishedState::handleClientPacket(pcpp::Packet& tcp_packet, const uint32_t tcp_hash,
                                         const pcpp::tcphdr& tcp_header, const uint32_t packet_size)
{
    if (tcp_header.ackFlag && !tcp_header.finFlag)
    {
        DpiEngine::getInstance().processDpiTcpPacket(tcp_packet);
        _context->updateSession(tcp_hash, TCP_COMMON_TYPES::ESTABLISHED, packet_size, true);
    }
    else if (tcp_header.finFlag)
    {
        // Active close from client
        _context->updateSession(tcp_hash, TCP_COMMON_TYPES::FIN_WAIT1, packet_size, true);
    }
    else
    {
        throw std::runtime_error("Invalid client packet in ESTABLISHED state: " + tcp_packet.toString());
    }
}

void EstablishedState::handleInternetPacket(pcpp::Packet& tcp_packet, const uint32_t tcp_hash,
                                           const pcpp::tcphdr& tcp_header, const uint32_t packet_size)
{
    if (tcp_header.ackFlag && !tcp_header.finFlag)
    {
        DpiEngine::getInstance().processDpiTcpPacket(tcp_packet);
        _context->updateSession(tcp_hash, TCP_COMMON_TYPES::ESTABLISHED, packet_size, false);
    }
    else if (tcp_header.finFlag) {
        // Active close from internet
        _context->updateSession(tcp_hash, TCP_COMMON_TYPES::CLOSE_WAIT, packet_size, false);
    }
    else {
        throw std::runtime_error("Invalid internet packet in ESTABLISHED state: " + tcp_packet.toString());
    }
}

// FinWait1State implementation
void FinWait1State::handleClientPacket(pcpp::Packet& tcp_packet, const uint32_t tcp_hash,
                                      const pcpp::tcphdr& tcp_header, const uint32_t packet_size)
{
    if (tcp_header.finFlag) {
        // FIN retransmission
        _context->updateSession(tcp_hash, TCP_COMMON_TYPES::FIN_WAIT1, packet_size, true);
    }
    else if (tcp_header.ackFlag)
    {
        _context->updateSession(tcp_hash, TCP_COMMON_TYPES::FIN_WAIT1, packet_size, true);
    }
    else {
        throw std::runtime_error("Invalid client packet in FIN_WAIT1 state: " + tcp_packet.toString());
    }
}

void FinWait1State::handleInternetPacket(pcpp::Packet& tcp_packet, const uint32_t tcp_hash,
                                        const pcpp::tcphdr& tcp_header, const uint32_t packet_size)
{
    if (tcp_header.ackFlag && !tcp_header.finFlag) {
        _context->updateSession(tcp_hash, TCP_COMMON_TYPES::FIN_WAIT2, packet_size, false);
    }
    else if (tcp_header.finFlag && tcp_header.ackFlag) {
        _context->updateSession(tcp_hash, TCP_COMMON_TYPES::TIME_WAIT, packet_size, false);
    }
    else {
        throw std::runtime_error("Invalid internet packet in FIN_WAIT1 state: " + tcp_packet.toString());
    }
}

// FinWait2State implementation
void FinWait2State::handleClientPacket(pcpp::Packet& tcp_packet, const uint32_t tcp_hash,
                                      const pcpp::tcphdr& tcp_header, const uint32_t packet_size)
{
    if (tcp_header.ackFlag)
    {
        _context->updateSession(tcp_hash, TCP_COMMON_TYPES::FIN_WAIT2, packet_size, true);
    }
    else {
        throw std::runtime_error("Invalid client packet in FIN_WAIT2 state: " + tcp_packet.toString());
    }
}

void FinWait2State::handleInternetPacket(pcpp::Packet& tcp_packet, const uint32_t tcp_hash,
                                        const pcpp::tcphdr& tcp_header, const uint32_t packet_size)
{
    if (tcp_header.ackFlag && !tcp_header.finFlag) {
        // Delayed data transfer
        _context->updateSession(tcp_hash, TCP_COMMON_TYPES::FIN_WAIT2, packet_size, false);
    }
    else if (tcp_header.finFlag) {
        _context->updateSession(tcp_hash, TCP_COMMON_TYPES::TIME_WAIT, packet_size, false);
    }
    else {
        throw std::runtime_error("Invalid internet packet in FIN_WAIT2 state: " + tcp_packet.toString());
    }
}

// CloseWaitState implementation
void CloseWaitState::handleClientPacket(pcpp::Packet& tcp_packet, const uint32_t tcp_hash,
                                       const pcpp::tcphdr& tcp_header, const uint32_t packet_size)
{
    if (tcp_header.ackFlag && !tcp_header.finFlag)
    {
        _context->updateSession(tcp_hash, TCP_COMMON_TYPES::CLOSE_WAIT, packet_size, true);
    }
    else if (tcp_header.finFlag)
    {
        _context->updateSession(tcp_hash, TCP_COMMON_TYPES::LAST_ACK, packet_size, true);
    }
    else {
        throw std::runtime_error("Invalid client packet in CLOSE_WAIT state: " + tcp_packet.toString());
    }
}

void CloseWaitState::handleInternetPacket(pcpp::Packet& tcp_packet, const uint32_t tcp_hash,
                                         const pcpp::tcphdr& tcp_header, const uint32_t packet_size)
{
    if (tcp_header.finFlag)
    {
        // FIN retransmissions
        _context->updateSession(tcp_hash, TCP_COMMON_TYPES::CLOSE_WAIT, packet_size, false);
    }
    else if (tcp_header.ackFlag)
    {
        // Delayed data transfer
        _context->updateSession(tcp_hash, TCP_COMMON_TYPES::CLOSE_WAIT, packet_size, false);
    }
    else {
        throw std::runtime_error("Invalid internet packet in CLOSE_WAIT state: " + tcp_packet.toString());
    }
}

// LastAckState implementation
void LastAckState::handleClientPacket(pcpp::Packet& tcp_packet, const uint32_t tcp_hash,
                                     const pcpp::tcphdr& tcp_header, const uint32_t packet_size)
{
    if (tcp_header.finFlag) {
        // FIN retransmissions
        _context->updateSession(tcp_hash, TCP_COMMON_TYPES::LAST_ACK, packet_size, true);
    }
    else {
        throw std::runtime_error("Invalid client packet in LAST_ACK state: " + tcp_packet.toString());
    }
}

void LastAckState::handleInternetPacket(pcpp::Packet& tcp_packet, const uint32_t tcp_hash,
                                       const pcpp::tcphdr& tcp_header, const uint32_t packet_size)
{
    if (tcp_header.ackFlag) {
        _context->updateSession(tcp_hash, TCP_COMMON_TYPES::TIME_WAIT, packet_size, false);
    }
    else {
        throw std::runtime_error("Invalid internet packet in LAST_ACK state: " + tcp_packet.toString());
    }
}

// TimeWaitState implementation
void TimeWaitState::handleClientPacket(pcpp::Packet& tcp_packet, const uint32_t tcp_hash,
                                      const pcpp::tcphdr& tcp_header, const uint32_t packet_size)
{
    if (tcp_header.ackFlag) {
        // Duplicate ACKs due to bad connection
        _context->updateSession(tcp_hash, TCP_COMMON_TYPES::TIME_WAIT, packet_size, true);
    }
    else {
        throw std::runtime_error("Invalid client packet in TIME_WAIT state: " + tcp_packet.toString());
    }
}

void TimeWaitState::handleInternetPacket(pcpp::Packet& tcp_packet, const uint32_t tcp_hash,
                                        const pcpp::tcphdr& tcp_header, const uint32_t packet_size)
{
    if (tcp_header.ackFlag || tcp_header.finFlag)
    {
        // Duplicate ACKs or FINs due to bad connection
        _context->updateSession(tcp_hash, TCP_COMMON_TYPES::TIME_WAIT, packet_size, false);
    }
    else {
        throw std::runtime_error("Invalid internet packet in TIME_WAIT state: " + tcp_packet.toString());
    }
}

// UnknownState implementation (fallback)
void UnknownState::handleClientPacket(pcpp::Packet& tcp_packet, uint32_t tcp_hash, 
                                     const pcpp::tcphdr& tcp_header, uint32_t packet_size)
{
    throw std::runtime_error("Cannot process packet in UNKNOWN state: " + tcp_packet.toString());
}

void UnknownState::handleInternetPacket(pcpp::Packet& tcp_packet, uint32_t tcp_hash, 
                                       const pcpp::tcphdr& tcp_header, uint32_t packet_size)
{
    throw std::runtime_error("Cannot process packet in UNKNOWN state: " + tcp_packet.toString());
}