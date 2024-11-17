#include "TcpSessionHandler.hpp"

TcpSessionHandler::TcpSessionHandler(): _session_table(SessionTable::getInstance()) {
}

std::unique_ptr<TcpSession> TcpSessionHandler::initTcpSession(const pcpp::Packet &tcp_packet, uint32_t seq_number, uint32_t ack_number)
{
    const pcpp::IPv4Layer* ipv4_layer = tcp_packet.getLayerOfType<pcpp::IPv4Layer>();
    const pcpp::TcpLayer* tcp_layer = tcp_packet.getLayerOfType<pcpp::TcpLayer>();
    const pcpp::IPv4Address src_ip = ipv4_layer->getSrcIPv4Address();
    const pcpp::IPv4Address dst_ip = ipv4_layer->getDstIPv4Address();
    const uint16_t src_port = pcpp::netToHost16(tcp_layer->getSrcPort());
    const uint16_t dst_port = pcpp::netToHost16(tcp_layer->getDstPort());
    auto session = std::make_unique<TcpSession>();
    session->dst_ip = dst_ip;
    session->source_ip = src_ip;
    session->dst_port = dst_port;
    session->source_port = src_port;
    session->current_ack = ack_number;
    session->current_seq = seq_number;
    return session;

}

void TcpSessionHandler::sendRstToClient(const pcpp::Packet &tcp_packet)
{
    pcpp::EthLayer* eth_layer = tcp_packet.getLayerOfType<pcpp::EthLayer>();
    pcpp::IPv4Layer* ipv4_layer = tcp_packet.getLayerOfType<pcpp::IPv4Layer>();
    pcpp::TcpLayer* tcp_layer = tcp_packet.getLayerOfType<pcpp::TcpLayer>();

    pcpp::Packet rst_packet(100);

    pcpp::MacAddress dst_mac = eth_layer->getSourceMac(); // Destination MAC becomes source MAC
    pcpp::MacAddress src_mac = eth_layer->getDestMac(); // source MAC becomes Destination MAC
    pcpp::EthLayer new_eth_layer(src_mac,dst_mac,PCPP_ETHERTYPE_IP);
    rst_packet.addLayer(&new_eth_layer);

    pcpp::IPv4Layer new_ip_layer(ipv4_layer->getDstIPv4Address(),ipv4_layer->getSrcIPv4Address());
    new_ip_layer.getIPv4Header()->timeToLive = 64;
    rst_packet.addLayer(&new_ip_layer);

    pcpp::TcpLayer new_tcp_layer(tcp_layer->getDstPort(),tcp_layer->getSrcPort());
    new_tcp_layer.getTcpHeader()->rstFlag = 1;  // Set RST flag
    new_tcp_layer.getTcpHeader()->ackFlag = 1;  // Acknowledge the last packet
    new_tcp_layer.getTcpHeader()->sequenceNumber = tcp_layer->getTcpHeader()->ackNumber; // Use the acknowledgment number as the sequence number
    new_tcp_layer.getTcpHeader()->ackNumber = tcp_layer->getTcpHeader()->sequenceNumber + 1; // Acknowledge the received packet
    rst_packet.addLayer(&new_tcp_layer);

    rst_packet.computeCalculateFields();
    const auto device  = pcpp::DpdkDeviceList::getInstance().getDeviceByPort(DPDK_DEVICE_1);
    if(!device->sendPacket(rst_packet)) {
        std::cerr << "Failed to send RST packet" << std::endl;
    }
    else {
        std::cout << "RST packet sent successfully" << std::endl;
    }
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

void TcpSessionHandler::processClientTcpPacket(pcpp::Packet* tcp_packet)
{
    //TODO: apply ip and port filter here - if(allow) open session else- close the session
    const uint32_t tcp_hash = hash5Tuple(tcp_packet);
    if(tcp_hash != 0)
    {
        const auto tcp_header = extractTcpHeader(*tcp_packet);
        if(_session_table.isSessionExists(tcp_hash)) //session is already exists
        {
            const auto current_state = _session_table.getCurrentState(tcp_hash);
            if(current_state == SYN_RECEIVED && tcp_header->ackFlag) {
                _session_table.updateSession(tcp_hash,ESTABLISHED);
            }
            else if(current_state == ESTABLISHED && tcp_header->ackFlag) {
                //data transfer
            }
            else if(current_state == ESTABLISHED && tcp_header->finFlag) {
                _session_table.updateSession(tcp_hash,FIN_WAIT1);
            }
            else if (current_state == FIN_WAIT2 && tcp_header->ackFlag) {
                _session_table.updateSession(tcp_hash,TIME_WAIT);
            }
            else {
                std::cout << "Unexpected TCP packet from Client" << std::endl;
            }
        }
        else //open a new session
        {
            if(tcp_header->synFlag) {
                auto new_session = initTcpSession(*tcp_packet,tcp_header->sequenceNumber,tcp_header->ackNumber);
                _session_table.addNewSession(tcp_hash,std::move(new_session), SYN_SENT);
            }
            else {
                //part of mid-connection session, not allow it for now: close the session by send RST to client;
                //sendRstToClient(*tcp_packet);
                std::cout << "part of mid-connection session" << std::endl;
            }
        }
    }
}

void TcpSessionHandler::processInternetTcpPacket(pcpp::Packet *tcp_packet)
{
    const uint32_t tcp_hash = hash5Tuple(tcp_packet);
    if(tcp_hash != 0 && _session_table.isSessionExists(tcp_hash))
    {
        const auto tcp_header = extractTcpHeader(*tcp_packet);
        const auto current_state = _session_table.getCurrentState(tcp_hash);
        if(current_state == SYN_SENT && tcp_header->synFlag && tcp_header->ackFlag) {
            _session_table.updateSession(tcp_hash,SYN_RECEIVED);
        }
        else if(current_state == ESTABLISHED && tcp_header->ackFlag) {
            //data transfer
        }
        else if(current_state == FIN_WAIT1 && tcp_header->ackFlag) {
            _session_table.updateSession(tcp_hash,CLOSE_WAIT);
        }
        else if(current_state == CLOSE_WAIT && tcp_header->finFlag) {
            _session_table.updateSession(tcp_hash,FIN_WAIT2);
        }
        else if (current_state == FIN_WAIT1 && tcp_header->finFlag && tcp_header->ackFlag) {
            _session_table.updateSession(tcp_hash,FIN_WAIT2);
        }
        else {
            std::cout << "Unexpected TCP packet from Internet" << std::endl;
        }
    }
}
