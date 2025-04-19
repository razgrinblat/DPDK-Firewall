#include "FtpControlHandler.hpp"

FtpControlHandler & FtpControlHandler::getInstance()
{
    static FtpControlHandler instance;
    return instance;
}

void FtpControlHandler::handleFtpPacket(pcpp::Packet& ftp_packet)
{
    const pcpp::TcpLayer* tcp_layer = ftp_packet.getLayerOfType<pcpp::TcpLayer>();
    if (tcp_layer->getDstPort() == Config::FTP_PORT) // Ftp Request
    {
        const auto request_layer =  ftp_packet.getLayerOfType<pcpp::FtpRequestLayer>();
        handleFtpRequest(*request_layer);
    }
    else if(tcp_layer->getSrcPort() == Config::FTP_PORT) // Ftp Response
    {
        const auto response_layer =  ftp_packet.getLayerOfType<pcpp::FtpResponseLayer>();
        handleFtpResponse(*response_layer);
    }
}

bool FtpControlHandler::isPassiveFtpSession(const std::unique_ptr<SessionTable::Session>& session)
{
    std::lock_guard lock(_table_mutex);

    return (_passive_table.find(session->dst_port) != _passive_table.end() &&
        _passive_table[session->dst_port] == session->dst_ip.toString());
}

void FtpControlHandler::handleFtpRequest(const pcpp::FtpRequestLayer& request_layer)
{
    if (request_layer.getCommand() == pcpp::FtpRequestLayer::FtpCommand::PASV) //passive mode
    {

    }
    else if (request_layer.getCommand() == pcpp::FtpRequestLayer::FtpCommand::PORT) //active mode
    {

    }
}

void FtpControlHandler::handleFtpResponse(const pcpp::FtpResponseLayer& response_layer)
{
    // passive mode dest ip and dest port transfer
    if (response_layer.getStatusCode() == pcpp::FtpResponseLayer::FtpStatusCode::ENTERING_PASSIVE)
    {
        const std::string response = response_layer.getStatusOption();
        if (const auto result = parsePasvResponseToIpPort(response))
        {
            const auto&[ip, port] = result.value();
            std::cout << "IP: " << ip.toString() << " Port: " << port << std::endl;
            std::lock_guard lock(_table_mutex);
            _passive_table[port] = ip.toString();
        }
    }
}

std::optional<std::vector<int>> FtpControlHandler::extractPasvNumbers(const std::string &response)
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
            return {};
        }
    }

    return parts;
}

std::optional<std::pair<pcpp::IPv4Address, uint16_t>> FtpControlHandler::parsePasvResponseToIpPort(
    const std::string &response)
{
    auto parts_opt = extractPasvNumbers(response);
    if (!parts_opt.has_value())
        return {};

    const auto& parts = parts_opt.value();
    const std::string ipStr = std::to_string(parts[0]) + "." + std::to_string(parts[1]) + "." +
                              std::to_string(parts[2]) + "." + std::to_string(parts[3]);

    uint16_t port = static_cast<uint16_t>(parts[4] * 256 + parts[5]);

    pcpp::IPv4Address ip(ipStr);
    if (!ip.isValid())
        return {};

    return std::make_pair(ip, port);
}