#include "TcpSessionHandler.hpp"

TcpSessionHandler::TcpSessionHandler(): _session_table(SessionTable::getInstance()), _dpi_engine(DpiEngine::getInstance())
{}

std::unique_ptr<SessionTable::TcpSession> TcpSessionHandler::initTcpSession(const pcpp::Packet &tcp_packet)
{
    const pcpp::IPv4Layer* ipv4_layer = tcp_packet.getLayerOfType<pcpp::IPv4Layer>();
    const pcpp::TcpLayer* tcp_layer = tcp_packet.getLayerOfType<pcpp::TcpLayer>();
    return std::make_unique<SessionTable::TcpSession>(
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

bool TcpSessionHandler::processClientTcpPacket(pcpp::Packet &tcp_packet)
{
    const uint32_t tcp_hash = hash5Tuple(&tcp_packet,false);

    const auto tcp_header = extractTcpHeader(tcp_packet);
    if(_session_table.isSessionExists(tcp_hash)) //session is already exists
    {
        const auto current_state = _session_table.getCurrentState(tcp_hash);
        if (tcp_header.rstFlag) {
        _session_table.updateSession(tcp_hash,SessionTable::TIME_WAIT);
        }
        // SYN_SENT syn retransmissions
        else if (current_state == SessionTable::SYN_SENT && tcp_header.synFlag) {
            _session_table.updateSession(tcp_hash,SessionTable::SYN_SENT);
        }
        else if(current_state == SessionTable::SYN_RECEIVED && tcp_header.ackFlag && !tcp_header.finFlag) {
            _session_table.updateSession(tcp_hash,SessionTable::ESTABLISHED);
        }
        else if(current_state == SessionTable::ESTABLISHED && tcp_header.ackFlag && !tcp_header.finFlag) {
            _session_table.updateSession(tcp_hash,SessionTable::ESTABLISHED);
        }

        //handle ACTIVE CLOSE from the client
        else if(current_state == SessionTable::ESTABLISHED && tcp_header.finFlag) {
            _session_table.updateSession(tcp_hash,SessionTable::FIN_WAIT1);
        }
        //FIN_WAIT1 fin retransmissions
        else if(current_state == SessionTable::FIN_WAIT1 && tcp_header.finFlag) {
            _session_table.updateSession(tcp_hash,SessionTable::FIN_WAIT1);
        }
        else if(current_state == SessionTable::FIN_WAIT1 && tcp_header.ackFlag) {
            _session_table.updateSession(tcp_hash,SessionTable::FIN_WAIT1);
        }
        else if (current_state == SessionTable::FIN_WAIT2 && tcp_header.ackFlag) {
            _session_table.updateSession(tcp_hash,SessionTable::FIN_WAIT2);
        }

        //handle PASSIVE CLOSE from the client
        else if (current_state == SessionTable::CLOSE_WAIT && tcp_header.ackFlag && !tcp_header.finFlag) {
            _session_table.updateSession(tcp_hash,SessionTable::CLOSE_WAIT);
        }
        else if (current_state == SessionTable::CLOSE_WAIT && tcp_header.finFlag) {
            _session_table.updateSession(tcp_hash,SessionTable::LAST_ACK);
        }
        //LAST_ACK fin retransmissions, server dont confirmed yet client's fin with ack
        else if (current_state == SessionTable::LAST_ACK && tcp_header.finFlag) {
            _session_table.updateSession(tcp_hash,SessionTable::LAST_ACK);
        }

        else if (current_state == SessionTable::TIME_WAIT && tcp_header.ackFlag) {
            //dup ACK's due to bad connection
        }
        else {
            return false;
        }
    }
    else //open a new session
    {
        if(tcp_header.synFlag) {
            auto new_session = initTcpSession(tcp_packet);
            _session_table.addNewSession(tcp_hash,std::move(new_session), SessionTable::SYN_SENT);
        }
        else {
            return false;
        }
    }
    //data transfer, DPI checking
    _dpi_engine.processDpiTcpPacket(tcp_packet);

    return _session_table.isAllowed(tcp_hash);
}

bool TcpSessionHandler::processInternetTcpPacket(pcpp::Packet& tcp_packet)
{
    const uint32_t tcp_hash = hash5Tuple(&tcp_packet,false);

    if(_session_table.isSessionExists(tcp_hash))
    {
        const auto tcp_header = extractTcpHeader(tcp_packet);
        const auto current_state = _session_table.getCurrentState(tcp_hash);

        if (tcp_header.rstFlag) {
        _session_table.updateSession(tcp_hash,SessionTable::TIME_WAIT);
        }
        else if(current_state == SessionTable::SYN_SENT && tcp_header.synFlag && tcp_header.ackFlag) {
            _session_table.updateSession(tcp_hash,SessionTable::SYN_RECEIVED);
        }
        //handle SYN_RECEIVED retransmissions
        else if (current_state == SessionTable::SYN_RECEIVED && tcp_header.synFlag && tcp_header.ackFlag) {
            _session_table.updateSession(tcp_hash,SessionTable::SYN_RECEIVED);
        }
        else if(current_state == SessionTable::ESTABLISHED && tcp_header.ackFlag && !tcp_header.finFlag) {
            _session_table.updateSession(tcp_hash,SessionTable::ESTABLISHED);
        }
        //handle PASSIVE CLOSE from the internet
        else if(current_state == SessionTable::FIN_WAIT1 && tcp_header.ackFlag && !tcp_header.finFlag) {
            _session_table.updateSession(tcp_hash,SessionTable::FIN_WAIT2);
        }
        else if (current_state == SessionTable::FIN_WAIT1 && tcp_header.finFlag && tcp_header.ackFlag) {
            _session_table.updateSession(tcp_hash,SessionTable::TIME_WAIT);
        }
        else if(current_state == SessionTable::FIN_WAIT2 && tcp_header.ackFlag && !tcp_header.finFlag) {
            //DELAYED DATA TRANSFER
            _session_table.updateSession(tcp_hash,SessionTable::FIN_WAIT2);
        }
        else if (current_state == SessionTable::FIN_WAIT2 && tcp_header.finFlag) {
            _session_table.updateSession(tcp_hash,SessionTable::TIME_WAIT);
        }

        //handle ACTIVE CLOSE from the internet
        else if (current_state == SessionTable::ESTABLISHED && tcp_header.finFlag) {
            _session_table.updateSession(tcp_hash,SessionTable::CLOSE_WAIT);
        }
        // CLOSE_WAIT fin retransmissions
        else if (current_state == SessionTable::CLOSE_WAIT && tcp_header.finFlag) {
            _session_table.updateSession(tcp_hash,SessionTable::CLOSE_WAIT);
        }
        else if (current_state == SessionTable::CLOSE_WAIT && tcp_header.ackFlag) {
            //DELAYED DATA TRANSFER
            _session_table.updateSession(tcp_hash,SessionTable::CLOSE_WAIT);
        }
        else if (current_state == SessionTable::LAST_ACK && tcp_header.ackFlag) {
            _session_table.updateSession(tcp_hash,SessionTable::TIME_WAIT);
        }

        else if (current_state == SessionTable::TIME_WAIT && (tcp_header.ackFlag || tcp_header.finFlag)) {
            //dup ACK's due to bad connection
        }

        else {
            const auto ip_layer = tcp_packet.getLayerOfType<pcpp::IPv4Layer>();
            std::cerr << "Blocked Unexpected TCP packet from Internet -IP: " << ip_layer->getSrcIPv4Address() << std::endl;
            return false; // block the packet
        }
    }
    else
    {
        const auto ip_layer = tcp_packet.getLayerOfType<pcpp::IPv4Layer>();
         if(!_session_table.isDstIpInCache(ip_layer->getSrcIPv4Address()))
         {
             std::cerr << "Blocked Unexpected TCP packet from IP: " << ip_layer->getSrcIPv4Address() << std::endl;
             return false;
         }
    }
    //data transfer, DPI checking
    _dpi_engine.processDpiTcpPacket(tcp_packet);

    return _session_table.isAllowed(tcp_hash);
}
