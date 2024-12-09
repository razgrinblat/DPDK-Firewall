#include "TcpSessionHandler.hpp"

TcpSessionHandler::TcpSessionHandler(): _session_table(SessionTable::getInstance()) {
}

std::unique_ptr<TcpSession> TcpSessionHandler::initTcpSession(const pcpp::Packet &tcp_packet, const uint32_t seq_number, const uint32_t ack_number)
{
    const pcpp::IPv4Layer* ipv4_layer = tcp_packet.getLayerOfType<pcpp::IPv4Layer>();
    const pcpp::TcpLayer* tcp_layer = tcp_packet.getLayerOfType<pcpp::TcpLayer>();
    const pcpp::IPv4Address src_ip = ipv4_layer->getSrcIPv4Address();
    const pcpp::IPv4Address dst_ip = ipv4_layer->getDstIPv4Address();
    const uint16_t src_port = tcp_layer->getSrcPort();
    const uint16_t dst_port = tcp_layer->getDstPort();
    auto session = std::make_unique<TcpSession>();
    session->dst_ip = dst_ip;
    session->source_ip = src_ip;
    session->dst_port = dst_port;
    session->source_port = src_port;
    session->current_ack = ack_number;
    session->current_seq = seq_number;
    session->current_state = UNKNOWN;
    return session;
}

pcpp::tcphdr *TcpSessionHandler::extractTcpHeader(const pcpp::Packet &tcp_packet)
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
    //TODO: apply ip and port filter here - if(allow) open session else- close the session
    const uint32_t tcp_hash = hash5Tuple(tcp_packet,false);
    if(tcp_hash != 0)
    {
        const auto tcp_header = extractTcpHeader(*tcp_packet);
        if(_session_table.isSessionExists(tcp_hash)) //session is already exists
        {
            const auto current_state = _session_table.getCurrentState(tcp_hash);
            if (tcp_header->rstFlag) {
            _session_table.updateSession(tcp_hash,TIME_WAIT);
            }
            else if(current_state == SYN_RECEIVED && tcp_header->ackFlag) {
                _session_table.updateSession(tcp_hash,ESTABLISHED);
            }
            else if(current_state == ESTABLISHED && tcp_header->ackFlag && !tcp_header->finFlag) {
                //data transfer, DPI checking in the future
            }
            //handle ACTIVE CLOSE from the client
            else if(current_state == ESTABLISHED && tcp_header->finFlag) {
                _session_table.updateSession(tcp_hash,FIN_WAIT1);
            }
            else if (current_state == FIN_WAIT2 && tcp_header->ackFlag) {
                _session_table.updateSession(tcp_hash,TIME_WAIT);
            }
            //handle PASSIVE CLOSE from the client
            else if (current_state == FIN_WAIT1 && tcp_header->ackFlag && !tcp_header->finFlag) {
                _session_table.updateSession(tcp_hash,CLOSE_WAIT);
            }
            else if (current_state == CLOSE_WAIT && tcp_header->finFlag) {
                _session_table.updateSession(tcp_hash,FIN_WAIT2);
            }
            else if (current_state == FIN_WAIT1 && tcp_header->ackFlag && tcp_header->finFlag) {
                _session_table.updateSession(tcp_hash,FIN_WAIT2);
            }
            //handle retransmissions connections
            else if (current_state == SYN_SENT && tcp_header->synFlag) {
                _session_table.updateSession(tcp_hash,SYN_SENT);
            }
            else if (current_state == TIME_WAIT && tcp_header->ackFlag) {
                //dup ack
            }
            else if (current_state == CLOSE_WAIT && tcp_header->ackFlag) {
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
                _session_table.addNewSession(tcp_hash,std::move(new_session), SYN_SENT);
            }
            else if (tcp_header->rstFlag) {
                _session_table.updateSession(tcp_hash,TIME_WAIT);
            }
            else {
                return false;
            }
        }
    }
    return true;
}

bool TcpSessionHandler::processInternetTcpPacket(pcpp::Packet *tcp_packet)
{
    const uint32_t tcp_hash = hash5Tuple(tcp_packet,false);

    if(tcp_hash != 0 && _session_table.isSessionExists(tcp_hash))
    {
        const auto tcp_header = extractTcpHeader(*tcp_packet);
        const auto current_state = _session_table.getCurrentState(tcp_hash);
        if (tcp_header->rstFlag) {
        _session_table.updateSession(tcp_hash,TIME_WAIT);
        }
        else if(current_state == SYN_SENT && tcp_header->synFlag && tcp_header->ackFlag) {
            _session_table.updateSession(tcp_hash,SYN_RECEIVED);
        }
        else if(current_state == ESTABLISHED && tcp_header->ackFlag && !tcp_header->finFlag) {
            //data transfer, DPI checking in the future
        }
        //handle PASSIVE CLOSE from the internet
        else if(current_state == FIN_WAIT1 && tcp_header->ackFlag && !tcp_header->finFlag) {
            _session_table.updateSession(tcp_hash,CLOSE_WAIT);
        }
        else if(current_state == CLOSE_WAIT && tcp_header->finFlag) {
            _session_table.updateSession(tcp_hash,FIN_WAIT2);
        }
        else if (current_state == FIN_WAIT1 && tcp_header->finFlag && tcp_header->ackFlag) {
            _session_table.updateSession(tcp_hash,FIN_WAIT2);
        }
        //handle ACTIVE CLOSE from the internet
        else if (current_state == ESTABLISHED && tcp_header->finFlag) {
            _session_table.updateSession(tcp_hash,FIN_WAIT1);
        }
        else if (current_state == FIN_WAIT2 && tcp_header->ackFlag) {
            _session_table.updateSession(tcp_hash,TIME_WAIT);
        }
        //handle retransmissions connections
        else if (current_state == SYN_RECEIVED && tcp_header->synFlag && tcp_header->ackFlag) {
            _session_table.updateSession(tcp_hash,SYN_RECEIVED);
        }
        //dup ack's
        else if (current_state == TIME_WAIT && tcp_header->ackFlag) {
            //dup ack
        }
        else if (current_state == CLOSE_WAIT && tcp_header->ackFlag) {
            //dup ack
        }
        else {
            std::cout << "Unexpected TCP packet from Internet - " << current_state << std::endl;
            return false; // block the packet
        }
    }
    return true;
}