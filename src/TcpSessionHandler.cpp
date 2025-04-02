#include "TcpSessionHandler.hpp"

TcpSessionHandler::TcpSessionHandler(): _session_table(SessionTable::getInstance()),
                                        _dpi_engine(DpiEngine::getInstance()), _port_allocator(PortAllocator::getInstance())
{}

std::unique_ptr<SessionTable::Session> TcpSessionHandler::initTcpSession(const pcpp::Packet &tcp_packet) const
{
    const pcpp::IPv4Layer* ipv4_layer = tcp_packet.getLayerOfType<pcpp::IPv4Layer>();
    const pcpp::TcpLayer* tcp_layer = tcp_packet.getLayerOfType<pcpp::TcpLayer>();
    return std::make_unique<SessionTable::Session>(
        SessionTable::TCP_PROTOCOL,
       ipv4_layer->getSrcIPv4Address(),
       ipv4_layer->getDstIPv4Address(),
       tcp_layer->getSrcPort(),
       tcp_layer->getDstPort(),
       SessionTable::UNKNOWN
   );
}

const pcpp::tcphdr& TcpSessionHandler::extractTcpHeader(const pcpp::Packet& tcp_packet)
{
    const pcpp::TcpLayer* tcp_layer = tcp_packet.getLayerOfType<pcpp::TcpLayer>();
    if (tcp_layer == nullptr) {
        throw std::runtime_error("No TCP layer found in this packet");
    }
    return *tcp_layer->getTcpHeader();
}

TcpSessionHandler & TcpSessionHandler::getInstance()
{
    static TcpSessionHandler instance;
    return instance;
}

void TcpSessionHandler::processClientTcpPacket(pcpp::Packet &tcp_packet)
{
    const uint32_t tcp_hash = hash5Tuple(&tcp_packet);

    const auto tcp_header = extractTcpHeader(tcp_packet);
    const uint32_t packet_size = tcp_packet.getRawPacket()->getRawDataLen();

    if(_session_table.isSessionExists(tcp_hash)) //session is already exists
    {
        const auto current_state = _session_table.getCurrentState(tcp_hash);
        if (tcp_header.rstFlag) {
        _session_table.updateSession(tcp_hash,SessionTable::TIME_WAIT, packet_size, true);
        }
        // SYN_SENT syn retransmissions
        else if (current_state == SessionTable::SYN_SENT && tcp_header.synFlag) {
            _session_table.updateSession(tcp_hash,SessionTable::SYN_SENT, packet_size, true);
        }
        else if(current_state == SessionTable::SYN_RECEIVED && tcp_header.ackFlag && !tcp_header.finFlag) {
            _session_table.updateSession(tcp_hash,SessionTable::ESTABLISHED, packet_size, true);
        }
        else if(current_state == SessionTable::ESTABLISHED && tcp_header.ackFlag && !tcp_header.finFlag) {
            _session_table.updateSession(tcp_hash,SessionTable::ESTABLISHED, packet_size, true);
        }

        //handle ACTIVE CLOSE from the client
        else if(current_state == SessionTable::ESTABLISHED && tcp_header.finFlag) {
            _session_table.updateSession(tcp_hash,SessionTable::FIN_WAIT1, packet_size, true);
        }
        //FIN_WAIT1 fin retransmissions
        else if(current_state == SessionTable::FIN_WAIT1 && tcp_header.finFlag) {
            _session_table.updateSession(tcp_hash,SessionTable::FIN_WAIT1, packet_size, true);
        }
        else if(current_state == SessionTable::FIN_WAIT1 && tcp_header.ackFlag) {
            _session_table.updateSession(tcp_hash,SessionTable::FIN_WAIT1, packet_size, true);
        }
        else if (current_state == SessionTable::FIN_WAIT2 && tcp_header.ackFlag) {
            _session_table.updateSession(tcp_hash,SessionTable::FIN_WAIT2, packet_size, true);
        }

        //handle PASSIVE CLOSE from the client
        else if (current_state == SessionTable::CLOSE_WAIT && tcp_header.ackFlag && !tcp_header.finFlag) {
            _session_table.updateSession(tcp_hash,SessionTable::CLOSE_WAIT, packet_size, true);
        }
        else if (current_state == SessionTable::CLOSE_WAIT && tcp_header.finFlag) {
            _session_table.updateSession(tcp_hash,SessionTable::LAST_ACK, packet_size, true);
        }
        //LAST_ACK fin retransmissions, server dont confirmed yet client's fin with ack
        else if (current_state == SessionTable::LAST_ACK && tcp_header.finFlag) {
            _session_table.updateSession(tcp_hash,SessionTable::LAST_ACK, packet_size, true);
        }

        else if (current_state == SessionTable::TIME_WAIT && tcp_header.ackFlag) {
            //dup ACK's due to bad connection
            _session_table.updateSession(tcp_hash,SessionTable::TIME_WAIT, packet_size, true);
        }
        else {
            throw std::runtime_error("un valid client packet1: " + tcp_packet.toString());
        }
    }
    else //open a new session
    {
        if(tcp_header.synFlag)
        {
            _session_table.addNewSession(tcp_hash,std::move(initTcpSession(tcp_packet)), SessionTable::SYN_SENT,packet_size);
        }
        else {
            throw std::runtime_error("un valid client packet2: " + tcp_packet.toString());
        }
    }

    //data transfer, DPI checking
    _dpi_engine.processDpiTcpPacket(tcp_packet);

    // change port to firewall port
    const auto tcp_layer = tcp_packet.getLayerOfType<pcpp::TcpLayer>();
    tcp_layer->getTcpHeader()->portSrc = pcpp::hostToNet16(_session_table.getFirewallPort(tcp_hash));

    if (!_session_table.isAllowed(tcp_hash)) throw std::runtime_error("packet blocked by DPI");
}

void TcpSessionHandler::isValidInternetTcpPacket(pcpp::Packet& tcp_packet)
{
    const uint32_t tcp_hash = hash5Tuple(&tcp_packet,false);

    if(_session_table.isSessionExists(tcp_hash))
    {
        const auto tcp_header = extractTcpHeader(tcp_packet);
        const auto current_state = _session_table.getCurrentState(tcp_hash);
        const uint32_t packet_size = tcp_packet.getRawPacket()->getRawDataLen();

        if (tcp_header.rstFlag) {
        _session_table.updateSession(tcp_hash,SessionTable::TIME_WAIT, packet_size, false);
        }
        else if(current_state == SessionTable::SYN_SENT && tcp_header.synFlag && tcp_header.ackFlag) {
            _session_table.updateSession(tcp_hash,SessionTable::SYN_RECEIVED, packet_size, false);
        }
        //handle SYN_RECEIVED retransmissions
        else if (current_state == SessionTable::SYN_RECEIVED && tcp_header.synFlag && tcp_header.ackFlag) {
            _session_table.updateSession(tcp_hash,SessionTable::SYN_RECEIVED, packet_size, false);
        }
        else if(current_state == SessionTable::ESTABLISHED && tcp_header.ackFlag && !tcp_header.finFlag) {
            _session_table.updateSession(tcp_hash,SessionTable::ESTABLISHED, packet_size, false);
        }
        //handle PASSIVE CLOSE from the internet
        else if(current_state == SessionTable::FIN_WAIT1 && tcp_header.ackFlag && !tcp_header.finFlag) {
            _session_table.updateSession(tcp_hash,SessionTable::FIN_WAIT2, packet_size, false);
        }
        else if (current_state == SessionTable::FIN_WAIT1 && tcp_header.finFlag && tcp_header.ackFlag) {
            _session_table.updateSession(tcp_hash,SessionTable::TIME_WAIT, packet_size, false);
        }
        else if(current_state == SessionTable::FIN_WAIT2 && tcp_header.ackFlag && !tcp_header.finFlag) {
            //DELAYED DATA TRANSFER
            _session_table.updateSession(tcp_hash,SessionTable::FIN_WAIT2, packet_size, false);
        }
        else if (current_state == SessionTable::FIN_WAIT2 && tcp_header.finFlag) {
            _session_table.updateSession(tcp_hash,SessionTable::TIME_WAIT, packet_size, false);
        }

        //handle ACTIVE CLOSE from the internet
        else if (current_state == SessionTable::ESTABLISHED && tcp_header.finFlag) {
            _session_table.updateSession(tcp_hash,SessionTable::CLOSE_WAIT, packet_size, false);
        }
        // CLOSE_WAIT fin retransmissions
        else if (current_state == SessionTable::CLOSE_WAIT && tcp_header.finFlag) {
            _session_table.updateSession(tcp_hash,SessionTable::CLOSE_WAIT, packet_size, false);
        }
        else if (current_state == SessionTable::CLOSE_WAIT && tcp_header.ackFlag) {
            //DELAYED DATA TRANSFER
            _session_table.updateSession(tcp_hash,SessionTable::CLOSE_WAIT, packet_size, false);
        }
        else if (current_state == SessionTable::LAST_ACK && tcp_header.ackFlag) {
            _session_table.updateSession(tcp_hash,SessionTable::TIME_WAIT, packet_size, false);
        }

        else if (current_state == SessionTable::TIME_WAIT && (tcp_header.ackFlag || tcp_header.finFlag)) {
            //dup ACK's due to bad connection
            _session_table.updateSession(tcp_hash,SessionTable::TIME_WAIT,packet_size,false);
        }
        else {
            throw std::runtime_error("Blocked Unexpected TCP packet from Internet: " + tcp_packet.toString());
        }
    }
    else
    {
        throw std::runtime_error("Blocked Unexpected TCP packet from Internet: " + tcp_packet.toString());
    }
    //data transfer, DPI checking
    _dpi_engine.processDpiTcpPacket(tcp_packet);

    if (!_session_table.isAllowed(tcp_hash)) throw std::runtime_error("packet blocked by DPI");
}