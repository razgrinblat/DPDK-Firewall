#include "FtpControlHandler.hpp"

FtpControlHandler::FtpControlHandler(): _session_table(SessionTable::getInstance())
{}

FtpControlHandler & FtpControlHandler::getInstance()
{
    static FtpControlHandler instance;
    return instance;
}

void FtpControlHandler::processFtpPacket(const pcpp::Packet& ftp_packet, const uint32_t session_hash)
{
    const pcpp::TcpLayer* tcp_layer = ftp_packet.getLayerOfType<pcpp::TcpLayer>();
    if (tcp_layer->getDstPort() == Config::FTP_PORT) // Ftp Request
    {
        const auto request_layer =  ftp_packet.getLayerOfType<pcpp::FtpRequestLayer>();
        handleFtpRequestCommand(*request_layer, ftp_packet, session_hash);
    }
    else if(tcp_layer->getSrcPort() == Config::FTP_PORT) // Ftp Response
    {
        const auto response_layer =  ftp_packet.getLayerOfType<pcpp::FtpResponseLayer>();
        handleFtpResponseStatus(*response_layer, ftp_packet, session_hash);
    }
}

void FtpControlHandler::isPassiveFtpSession(const std::unique_ptr<SessionTable::Session>& session, const uint32_t tcp_hash)
{
    std::lock_guard lock(_table_mutex);

    const PassiveKey passive_key(session->dst_ip,session->dst_port);
    if (_passive_table.find(passive_key) != _passive_table.end())
    {
        session->ftp_context.ftp_inspection = true;
        // save the data channel hash in the control channel session
        _session_table.setFtpDataSession(_passive_table[passive_key],tcp_hash);
    }
}

void FtpControlHandler::handleFtpRequestCommand(const pcpp::FtpRequestLayer& request_layer, const pcpp::Packet& ftp_packet, const uint32_t session_hash)
{
    const auto command = request_layer.getCommand();
    // passive mode
    if (command == pcpp::FtpRequestLayer::FtpCommand::PASV)
    {
        _session_table.setFtpRequestCommand(session_hash, command);
    }
    // get file
    else if (command == pcpp::FtpRequestLayer::FtpCommand::RETR &&
        _session_table.getFtpResponseStatus(session_hash) == pcpp::FtpResponseLayer::FtpStatusCode::ENTERING_PASSIVE)
    {
        const std::string requested_file = request_layer.getCommandOption();
        // TODO : BLOCK DOWNLOAD FILE NAMES
        //FtpDpiModule::getInstance().

        if (const auto result = _session_table.getFtpDataSession(session_hash))
        {
            const uint32_t data_channel_hash = result.value();
            _session_table.setFtpRequestCommand(data_channel_hash, pcpp::FtpRequestLayer::FtpCommand::RETR);
        }
    }
    else if (command == pcpp::FtpRequestLayer::FtpCommand::STOR &&
            _session_table.getFtpResponseStatus(session_hash) == pcpp::FtpResponseLayer::FtpStatusCode::ENTERING_PASSIVE)
    {
        const std::string requested_file = request_layer.getCommandOption();
        // TODO : BLOCK UPLOAD FILE NAMES
        //FtpDpiModule::getInstance().

        if (const auto result = _session_table.getFtpDataSession(session_hash))
        {
            const uint32_t data_channel_hash = result.value();
            _session_table.setFtpRequestCommand(data_channel_hash, pcpp::FtpRequestLayer::FtpCommand::STOR);
        }
    }
    else if (command == pcpp::FtpRequestLayer::FtpCommand::LIST &&
            _session_table.getFtpResponseStatus(session_hash) == pcpp::FtpResponseLayer::FtpStatusCode::ENTERING_PASSIVE)
    {
        if (const auto result = _session_table.getFtpDataSession(session_hash))
        {
            const uint32_t data_channel_hash = result.value();
            _session_table.setFtpRequestCommand(data_channel_hash, pcpp::FtpRequestLayer::FtpCommand::LIST);
        }
    }

    else if (command == pcpp::FtpRequestLayer::FtpCommand::PORT) //active mode
    {

    }
}

void FtpControlHandler::handleFtpResponseStatus(const pcpp::FtpResponseLayer& response_layer, const pcpp::Packet& ftp_packet,
    const uint32_t session_hash)
{
    const auto status = response_layer.getStatusCode();
    // passive mode dest ip and dest port transfer
    if (status == pcpp::FtpResponseLayer::FtpStatusCode::ENTERING_PASSIVE)
    {
        if(_session_table.getFtpRequestCommand(session_hash) == pcpp::FtpRequestLayer::FtpCommand::PASV)
        {
            _session_table.setFtpResponseStatus(session_hash,status);

            const std::string response = response_layer.getStatusOption();
            if (const auto result = parseFtpMessageToIpPort(response))
            {
                const auto&[ip, port] = result.value();
                // TODO: drop the packet after creating session class
                std::cout << "IP: " << ip.toString() << " Port: " << port << std::endl;
                std::lock_guard lock(_table_mutex);
                _passive_table[{ip,port}] = session_hash;
            }
        }
        else throw std::runtime_error("Spoofed enter_passive packet: " + ftp_packet.toString());
    }
}

std::optional<std::vector<int>> FtpControlHandler::extractFtpNumbers(const std::string &response)
{
    const size_t start = response.find('(');
    const size_t end = response.find(')', start);
    if (start == std::string::npos || end == std::string::npos) return {};

    const std::string numbers_str = response.substr(start + 1, end - start - 1);
    std::stringstream ss(numbers_str);
    std::string token;
    std::vector<int> parts;

    while (std::getline(ss, token, ','))
    {
        try {
            parts.push_back(std::stoi(token));
        } catch (...) {
            return {}; // invalid number format
        }
    }
    return parts;
}


std::optional<std::pair<pcpp::IPv4Address, uint16_t>> FtpControlHandler::parseFtpMessageToIpPort(
    const std::string &response)
{
    auto parts_opt = extractFtpNumbers(response);
    if (!parts_opt.has_value())
        return {};

    const auto& parts = parts_opt.value();
    const std::string ipStr = std::to_string(parts[0]) + "." + std::to_string(parts[1]) + "." +
                              std::to_string(parts[2]) + "." + std::to_string(parts[3]);

    // combine two 8 bits number to one 16 bit port
    uint16_t port = static_cast<uint16_t>(parts[4] * FTP_PORT_BASE + parts[5]);

    pcpp::IPv4Address ip(ipStr);
    if (!ip.isValid())
        return {};

    return std::make_pair(ip, port);
}