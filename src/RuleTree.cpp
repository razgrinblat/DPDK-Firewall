#include "RuleTree.hpp"

RuleTree::RuleTree() : _root(std::make_shared<TreeNode>()),
                       _ip_rules_parser(IpRulesParser::getInstance(Config::IP_RULES_PATH))
{
    _file_watcher.addWatch(Config::IP_RULES_PATH, std::bind(&RuleTree::FileEventCallback, this));
    _file_watcher.startWatching();
}

std::shared_ptr<RuleTree::TreeNode> RuleTree::getOrCreateChild(const std::shared_ptr<TreeNode> &node, const std::string &key)
{
    if (node->children.find(key) == node->children.end())
    {
        node->children[key] = std::make_shared<TreeNode>();
    }
    return node->children[key];
}


void RuleTree::resetTree()
{
    std::unique_lock lock(_tree_mutex);
    _root = std::make_shared<TreeNode>();
}

void RuleTree::addRule(const Rule& rule)
{
    std::unique_lock lock(_tree_mutex);
    std::shared_ptr<TreeNode> current = _root;

    // Step 1: Protocol
    current = getOrCreateChild(current, rule.getProtocol());
    // Step 2: Source IP
    current = getOrCreateChild(current, rule.getSrcIp());
    // Step 3: Source Port
    current = getOrCreateChild(current, rule.getSrcPort());
    // Step 4: Destination IP
    current = getOrCreateChild(current, rule.getDstIp());
    // Step 5: Destination Port
    current = getOrCreateChild(current, rule.getDstPort());
    // Final: Set action
    current->action = rule.getAction();
}

void RuleTree::insertingRulesEventHandler(const std::vector<Rule> &current_rules)
{
    for (const auto& rule : current_rules)
    {
        addRule(rule);
        std::cout << "Adding new rule -> " << rule << std::endl;
    }
}

void RuleTree::FileEventCallback()
{
    try {
        _ip_rules_parser.loadRules();
    }
    catch (const std::runtime_error& e) {
        std::cerr << e.what() << std::endl;
        return;
    }
    const auto& current_rules = _ip_rules_parser.getCurrentRules();
    resetTree();
    insertingRulesEventHandler(current_rules);
}

RuleTree & RuleTree::getInstance()
{
    static RuleTree instance;
    return instance;
}

std::shared_ptr<RuleTree::TreeNode> RuleTree::findChildOrGeneric(const std::shared_ptr<TreeNode> &node,
    const std::string &key, const std::string &fall_back) const
{
    auto it = node->children.find(key);
    if (it != node->children.end())
        return it->second;

    auto fallback_it = node->children.find(fall_back);
    if (fallback_it != node->children.end())
        return fallback_it->second;

    return nullptr;
}

void RuleTree::buildTree()
{
    _ip_rules_parser.loadRules();
    for(const auto& rule : _ip_rules_parser.getCurrentRules())
    {
        addRule(rule);
    }
    std::cout << "Rules Tree built Successfully!" << std::endl;
}

bool RuleTree::isPacketAllowed(const std::string& protocol, const std::string& src_ip, const std::string& src_port,
    const std::string& dst_ip, const std::string& dst_port)
{
    std::shared_lock lock(_tree_mutex);
    std::shared_ptr<TreeNode> current = _root;

    // Step 1: Protocol check (must exist)
    auto proto_it = current->children.find(protocol);
    if (proto_it == current->children.end())
        return false;
    current = proto_it->second;

    // Step 2: Source IP (try specific, fallback to generic)
    current = findChildOrGeneric(current, src_ip, GENERIC_IP);
    if (!current) return false;

    // Step 3: Source Port (try specific, fallback to wildcard)
    current = findChildOrGeneric(current, src_port, "*");
    if (!current) return false;

    // Step 4: Destination IP (try specific, fallback to generic)
    current = findChildOrGeneric(current, dst_ip, GENERIC_IP);
    if (!current) return false;

    // Step 5: Destination Port (try specific, fallback to wildcard)
    current = findChildOrGeneric(current, dst_port, "*");
    if (!current) return false;

    // Final decision based on action field
    return current->action;
}

bool RuleTree::handleTcpLayer(const pcpp::Packet &packet, const std::string &src_ip,
    const std::string &dst_ip)
{
    const pcpp::TcpLayer* tcp_layer = packet.getLayerOfType<pcpp::TcpLayer>();
    if (!tcp_layer)
        return false; // corrupted packet

    const std::string src_port = std::to_string(tcp_layer->getSrcPort());
    const std::string dst_port = std::to_string(tcp_layer->getDstPort());

    // Check if the packet is allowed by the rule tree
    return isPacketAllowed("tcp", src_ip, src_port, dst_ip, dst_port);

}

bool RuleTree::handleUdpLayer(const pcpp::Packet &packet, const std::string &src_ip,
    const std::string &dst_ip)
{
        const pcpp::UdpLayer* udp_layer = packet.getLayerOfType<pcpp::UdpLayer>();
        if (!udp_layer)
            return false; // corrupted packet

        const std::string src_port = std::to_string(udp_layer->getSrcPort());
        const std::string dst_port = std::to_string(udp_layer->getDstPort());

        // Check if the packet is allowed by the rule tree
        return isPacketAllowed("udp", src_ip, src_port, dst_ip, dst_port);
}

bool RuleTree::handleOutboundForwarding(const pcpp::Packet &parsed_packet)
{
    const pcpp::IPv4Layer* ipv4_layer = parsed_packet.getLayerOfType<pcpp::IPv4Layer>();
    if (!ipv4_layer) {
        return false; // No IPv4 layer, cannot process the packet
    }

    const std::string src_ip = ipv4_layer->getSrcIPv4Address().toString();
    const std::string dst_ip = ipv4_layer->getDstIPv4Address().toString();

    if (parsed_packet.isPacketOfType(pcpp::UDP))
        return handleUdpLayer(parsed_packet, src_ip, dst_ip);

    if (parsed_packet.isPacketOfType(pcpp::TCP))
        return handleTcpLayer(parsed_packet, src_ip, dst_ip);

    return false; // unsupported layer
}