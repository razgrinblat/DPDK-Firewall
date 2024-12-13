#include "TcpSessionHandler.hpp"

TcpSessionHandler::TcpSessionHandler(): _session_table(SessionTable::getInstance()) {
}

std::unique_ptr<SessionTable::TcpSession> TcpSessionHandler::initTcpSession(const pcpp::Packet &tcp_packet, const uint32_t seq_number, const uint32_t ack_number)
{
    const pcpp::IPv4Layer* ipv4_layer = tcp_packet.getLayerOfType<pcpp::IPv4Layer>();
    const pcpp::TcpLayer* tcp_layer = tcp_packet.getLayerOfType<pcpp::TcpLayer>();
    return std::make_unique<SessionTable::TcpSession>(
       ipv4_layer->getSrcIPv4Address(),
       ipv4_layer->getDstIPv4Address(),
       tcp_layer->getSrcPort(),
       tcp_layer->getDstPort(),
       seq_number,
       ack_number,
       SessionTable::UNKNOWN
   );
}

pcpp::tcphdr *TcpSessionHandler::extractTcpHeader(const pcpp::Packet& tcp_packet)
{
    pcpp::TcpLayer* tcp_layer = tcp_packet.getLayerOfType<pcpp::TcpLayer>();
    if (tcp_layer == nullptr) {
        throw std::runtime_error("No TCP layer found in this packet");
    }
    return tcp_layer->getTcpHeader();
}

TcpSessionHandler::~TcpSessionHandler() {

}

TcpSessionHandler & TcpSessionHandler::getInstance()
{
    static TcpSessionHandler instance;
    return instance;
}

bool TcpSessionHandler::processClientTcpPacket(pcpp::Packet* tcp_packet)
{
    const uint32_t tcp_hash = hash5Tuple(tcp_packet,false);
    if(tcp_hash != 0)
    {
        const auto tcp_header = extractTcpHeader(*tcp_packet);
        if(_session_table.isSessionExists(tcp_hash)) //session is already exists
        {
            const auto current_state = _session_table.getCurrentState(tcp_hash);
            if (tcp_header->rstFlag) {
            _session_table.updateSession(tcp_hash,SessionTable::TIME_WAIT);
            }
            else if(current_state == SessionTable::SYN_RECEIVED && tcp_header->ackFlag) {
                _session_table.updateSession(tcp_hash,SessionTable::ESTABLISHED);
            }
            else if(current_state == SessionTable::ESTABLISHED && tcp_header->ackFlag && !tcp_header->finFlag) {
                //data transfer, DPI checking in the future
            }
            //handle ACTIVE CLOSE from the client
            else if(current_state == SessionTable::ESTABLISHED && tcp_header->finFlag) {
                _session_table.updateSession(tcp_hash,SessionTable::FIN_WAIT1);
            }
            else if (current_state == SessionTable::FIN_WAIT2 && tcp_header->ackFlag) {
                _session_table.updateSession(tcp_hash,SessionTable::TIME_WAIT);
            }
            //handle PASSIVE CLOSE from the client
            else if (current_state == SessionTable::FIN_WAIT1 && tcp_header->ackFlag && !tcp_header->finFlag) {
                _session_table.updateSession(tcp_hash,SessionTable::CLOSE_WAIT);
            }
            else if (current_state == SessionTable::CLOSE_WAIT && tcp_header->finFlag) {
                _session_table.updateSession(tcp_hash,SessionTable::FIN_WAIT2);
            }
            else if (current_state == SessionTable::FIN_WAIT1 && tcp_header->ackFlag && tcp_header->finFlag) {
                _session_table.updateSession(tcp_hash,SessionTable::FIN_WAIT2);
            }
            //handle retransmissions connections
            else if (current_state == SessionTable::SYN_SENT && tcp_header->synFlag) {
                _session_table.updateSession(tcp_hash,SessionTable::SYN_SENT);
            }
            else if (current_state == SessionTable::TIME_WAIT && tcp_header->ackFlag) {
                //dup ack
            }
            else if (current_state == SessionTable::CLOSE_WAIT && tcp_header->ackFlag) {
                //dup ack
            }
            else {
                std::cout << "test" << std::endl;
                return false;
            }
        }
        else //open a new session
        {
            if(tcp_header->synFlag) {
                auto new_session = initTcpSession(*tcp_packet,tcp_header->sequenceNumber,tcp_header->ackNumber);
                _session_table.addNewSession(tcp_hash,std::move(new_session), SessionTable::SYN_SENT);
            }
            else if (tcp_header->rstFlag) {
                _session_table.updateSession(tcp_hash,SessionTable::TIME_WAIT);
            }
            else {
                return false;
            }
        }
    }
    return true;
}

bool TcpSessionHandler::processInternetTcpPacket(pcpp::Packet* tcp_packet)
{
    const uint32_t tcp_hash = hash5Tuple(tcp_packet,false);

    if(tcp_hash != 0 && _session_table.isSessionExists(tcp_hash))
    {
        const auto tcp_header = extractTcpHeader(*tcp_packet);
        const auto current_state = _session_table.getCurrentState(tcp_hash);
        if (tcp_header->rstFlag) {
        _session_table.updateSession(tcp_hash,SessionTable::TIME_WAIT);
        }
        else if(current_state == SessionTable::SYN_SENT && tcp_header->synFlag && tcp_header->ackFlag) {
            _session_table.updateSession(tcp_hash,SessionTable::SYN_RECEIVED);
        }
        else if(current_state == SessionTable::ESTABLISHED && tcp_header->ackFlag && !tcp_header->finFlag) {
            //data transfer, DPI checking in the future
        }
        //handle PASSIVE CLOSE from the internet
        else if(current_state == SessionTable::FIN_WAIT1 && tcp_header->ackFlag && !tcp_header->finFlag) {
            _session_table.updateSession(tcp_hash,SessionTable::CLOSE_WAIT);
        }
        else if(current_state == SessionTable::CLOSE_WAIT && tcp_header->finFlag) {
            _session_table.updateSession(tcp_hash,SessionTable::FIN_WAIT2);
        }
        else if (current_state == SessionTable::FIN_WAIT1 && tcp_header->finFlag && tcp_header->ackFlag) {
            _session_table.updateSession(tcp_hash,SessionTable::FIN_WAIT2);
        }
        //handle ACTIVE CLOSE from the internet
        else if (current_state == SessionTable::ESTABLISHED && tcp_header->finFlag) {
            _session_table.updateSession(tcp_hash,SessionTable::FIN_WAIT1);
        }
        else if (current_state == SessionTable::FIN_WAIT2 && tcp_header->ackFlag) {
            _session_table.updateSession(tcp_hash,SessionTable::TIME_WAIT);
        }
        //handle retransmissions connections
        else if (current_state == SessionTable::SYN_RECEIVED && tcp_header->synFlag && tcp_header->ackFlag) {
            _session_table.updateSession(tcp_hash,SessionTable::SYN_RECEIVED);
        }
        //dup ack's
        else if (current_state == SessionTable::TIME_WAIT && tcp_header->ackFlag) {
            //dup ack
        }
        else if (current_state == SessionTable::CLOSE_WAIT && tcp_header->ackFlag) {
            //dup ack
        }
        else {
            const auto ip_layer = tcp_packet->getLayerOfType<pcpp::IPLayer>();
            std::cerr << "Unexpected TCP packet from Internet -IP: " << ip_layer->getSrcIPAddress() << std::endl;
            return false; // block the packet
        }
    }
    return true;
}