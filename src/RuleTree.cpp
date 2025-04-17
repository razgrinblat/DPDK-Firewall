#include "RuleTree.hpp"

RuleTree::RuleTree() : _root(std::make_shared<TreeNode>()),
                       _ip_rules_parser(IpRulesParser::getInstance(Config::IP_RULES_PATH)), _ws(WebSocketClient::getInstance())
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

std::shared_ptr<RuleTree::TreeNode> RuleTree::addNodeWithConflictCheck(const std::shared_ptr<TreeNode> &node,
    const std::string &key, const std::string &wild_card, const std::string &error_message)
{
    //Rule conflict because generic ip/port cant be above specific rule
    if (node->children.size() == 0)
    {
        return getOrCreateChild(node, key);
    }
    if (key != wild_card && node->children.find(wild_card) != node->children.end())
    {
        throw std::invalid_argument(error_message);
    }
    return getOrCreateChild(node, key);
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
    current = addNodeWithConflictCheck(current, rule.getSrcIp(), GENERIC_IP,
        "[RULE CONFLICT] Conflicting rules by Source IP address prevent adding rule: " + rule.getName() + ".\n Delete conflicting rules to proceed.");
    // Step 3: Source Port
    current = addNodeWithConflictCheck(current, rule.getSrcPort(), "*",
        "[RULE CONFLICT] Conflicting rules by Source Port number prevent adding rule: " + rule.getName() + ".\n Delete conflicting rules to proceed.");
    // Step 4: Destination IP
    current = addNodeWithConflictCheck(current, rule.getDstIp(), GENERIC_IP,
        "[RULE CONFLICT] Conflicting rules by Dest IP address prevent adding rule: " + rule.getName() + ".\n Delete conflicting rules to proceed.");
    // Step 5: Destination Port
    current = addNodeWithConflictCheck(current, rule.getDstPort(), "*",
        "[RULE CONFLICT] Conflicting rules by Destination Port number prevent adding rule: " + rule.getName() + ".\n Delete conflicting rules to proceed.");
    // Final: Set action
    current->action = rule.getAction();
}

void RuleTree::insertingRulesEventHandler(const std::vector<Rule> &current_rules)
{
    for (const auto& rule : current_rules)
    {
        try {
            addRule(rule);
            std::cout << "Adding new rule -> " << rule << std::endl;
        }
        catch (const std::invalid_argument& e) // there is a rule conflict
        {
            std::cerr << e.what() << std::endl;
            _ws.send(sendConflictedMsgToBackend(e.what()));
        }
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

std::string RuleTree::sendConflictedMsgToBackend(const std::string& msg)
{
    Json::Value rule_conflict;
    rule_conflict["type"] = "rule conflict";
    rule_conflict["message"] = msg;
    return rule_conflict.toStyledString();
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