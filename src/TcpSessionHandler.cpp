#include "TcpSessionHandler.hpp"

TcpSessionHandler::TcpSessionHandler() : _session_table(SessionTable::getInstance()),
    _dpi_engine(DpiEngine::getInstance()), _port_allocator(PortAllocator::getInstance()) {}

TcpSessionHandler& TcpSessionHandler::getInstance()
{
    static TcpSessionHandler instance;
    return instance;
}

std::unique_ptr<SessionTable::Session> TcpSessionHandler::initTcpSession(const pcpp::Packet& tcp_packet) const
{
    const auto* ipv4_layer = tcp_packet.getLayerOfType<pcpp::IPv4Layer>();
    const auto* tcp_layer = tcp_packet.getLayerOfType<pcpp::TcpLayer>();
    return std::make_unique<SessionTable::Session>(
        TCP_COMMON_TYPES::TCP_PROTOCOL,
        ipv4_layer->getSrcIPv4Address(),
        ipv4_layer->getDstIPv4Address(),
        tcp_layer->getSrcPort(),
        tcp_layer->getDstPort(),
        TCP_COMMON_TYPES::UNKNOWN);
}

const pcpp::tcphdr& TcpSessionHandler::extractTcpHeader(const pcpp::Packet& tcp_packet)
{
    const auto* tcp_layer = tcp_packet.getLayerOfType<pcpp::TcpLayer>();
    if (!tcp_layer) throw std::runtime_error("Missing TCP layer");
    return *tcp_layer->getTcpHeader();
}

void TcpSessionHandler::processClientTcpPacket(pcpp::Packet& tcp_packet)
{
    const uint32_t tcp_hash = hash5Tuple(&tcp_packet);
    const auto tcp_header = extractTcpHeader(tcp_packet);
    const uint32_t packet_size = tcp_packet.getRawPacket()->getRawDataLen();

    if (_session_table.isSessionExists(tcp_hash))
    {
        if (tcp_header.rstFlag)
        {
            _session_table.updateSession(tcp_hash, TCP_COMMON_TYPES::TIME_WAIT, packet_size, true, this);
        }
        else {
            const SessionTable::Session* session = _session_table.getSession(tcp_hash);
            session->state_object->handleClientPacket(tcp_packet, tcp_hash, tcp_header, packet_size);
        }
    }
    else
    {
        if (tcp_header.synFlag) {
            auto session = initTcpSession(tcp_packet);
            _session_table.addNewSession(tcp_hash, std::move(session), TCP_COMMON_TYPES::SYN_SENT, packet_size, this);
        }
        else {
            throw std::runtime_error("Invalid initial client packet");
        }
    }

    //change client src port to firewall src port (PAT)
    const auto* tcp_layer = tcp_packet.getLayerOfType<pcpp::TcpLayer>();
    tcp_layer->getTcpHeader()->portSrc = pcpp::hostToNet16(_session_table.getFirewallPort(tcp_hash));

    if (!_session_table.isAllowed(tcp_hash)) throw std::runtime_error("Blocked by DPI");
}

void TcpSessionHandler::isValidInternetTcpPacket(pcpp::Packet& tcp_packet)
{
    const uint32_t tcp_hash = hash5Tuple(&tcp_packet, false);
    const auto tcp_header = extractTcpHeader(tcp_packet);
    const uint32_t packet_size = tcp_packet.getRawPacket()->getRawDataLen();

    if (_session_table.isSessionExists(tcp_hash))
    {
        if (tcp_header.rstFlag)
        {
            _session_table.updateSession(tcp_hash, TCP_COMMON_TYPES::TIME_WAIT, packet_size, false, this);
        }
        else
        {
            const SessionTable::Session* session = _session_table.getSession(tcp_hash);
            session->state_object->handleInternetPacket(tcp_packet, tcp_hash, tcp_header, packet_size);
        }
    }
    else {
        throw std::runtime_error("Blocked unknown internet TCP packet");
    }

    if (!_session_table.isAllowed(tcp_hash)) throw std::runtime_error("Blocked by DPI");
}

void TcpSessionHandler::updateSession(const uint32_t tcp_hash, const SessionTable::TcpState new_state, const uint32_t packet_size, const bool is_outbound)
{
    _session_table.updateSession(tcp_hash, new_state, packet_size, is_outbound, this);
}