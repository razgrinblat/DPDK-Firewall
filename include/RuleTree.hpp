#pragma once
#include <Packet.h>
#include <unordered_map>
#include <TcpLayer.h>
#include <UdpLayer.h>
#include <IPv4Layer.h>
#include "IpRulesParser.hpp"
#include "InotifyWrapper.hpp"
#include "WebSocketClient.hpp"
#include <shared_mutex>

/**
 * @class RuleTree
 * @brief Singleton class for managing a hierarchical rule tree for packet filtering.
 *
 * This class supports dynamic rule insertion, wildcard matching,
 * and thread-safe evaluation of IPv4/TCP/UDP packet rules.
 */
class RuleTree
{
private:
    /**
     * @struct TreeNode
     * @brief Node in the rule tree containing child nodes and an action flag.
     */
    struct TreeNode
    {
        std::unordered_map<std::string, std::shared_ptr<TreeNode>> children; // Child nodes keyed by rule field value.
        bool action; // True - accept, False - block
    };

    std::shared_ptr<TreeNode> _root; // Root node of the rule tree.

    std::shared_mutex _tree_mutex; // Mutex for thread-safe read/write access.
    InotifyWrapper _file_watcher; // Watches for rule file changes.
    IpRulesParser& _ip_rules_parser; // Reference to IP rule parser.

    static constexpr auto GENERIC_IP = "*.*.*.*"; // Constant used for generic IP wildcard.

    /**
     * @brief Private constructor for singleton pattern.
     */
    RuleTree();

    /**
     * @brief Get or create a child node from a parent node.
     * @param node The parent node.
     * @param key Key to access or create a child.
     * @return Pointer to the child node.
     */
    std::shared_ptr<TreeNode> getOrCreateChild(const std::shared_ptr<TreeNode>& node, const std::string& key);

    void resetTree();

    /**
     * @brief Adds a rule to the rule tree.
     * @param rule The rule object to add.
     */
    void addRule(const Rule& rule);

    /**
     * @brief Handler for rule insertion event triggered by file change.
     * @param current_rules A list of current rules to insert.
     */
    void insertingRulesEventHandler(const std::vector<Rule>& current_rules);

    /**
     * @brief Callback triggered when the rule file is updated.
     */
    void FileEventCallback();

    /**
     * @brief Tries to find a child node by specific key or fallback wildcard.
     * @param node The current node.
     * @param key The specific key to match.
     * @param fall_back Fallback wildcard value.
     * @return Pointer to the matched child or nullptr.
     */
    std::shared_ptr<TreeNode> findChildOrGeneric(const std::shared_ptr<TreeNode>& node,
                                                 const std::string& key,
                                                 const std::string& fall_back) const;

    /**
     * @brief Checks if a packet is allowed based on current rule tree.
     * @param protocol Packet protocol ("tcp", "udp").
     * @param src_ip Source IP address.
     * @param src_port Source port.
     * @param dst_ip Destination IP address.
     * @param dst_port Destination port.
     * @return True if allowed, false if blocked.
     */
    bool isPacketAllowed(const std::string& protocol,
                         const std::string& src_ip,
                         const std::string& src_port,
                         const std::string& dst_ip,
                         const std::string& dst_port);

    /**
     * @brief Handles TCP packet inspection using rule tree.
     * @param packet Parsed TCP packet.
     * @param src_ip Source IP address.
     * @param dst_ip Destination IP address.
     * @return True if allowed, false otherwise.
     */
    bool handleTcpLayer(const pcpp::Packet& packet, const std::string& src_ip, const std::string& dst_ip);

    /**
     * @brief Handles UDP packet inspection using rule tree.
     * @param packet Parsed UDP packet.
     * @param src_ip Source IP address.
     * @param dst_ip Destination IP address.
     * @return True if allowed, false otherwise.
     */
    bool handleUdpLayer(const pcpp::Packet& packet, const std::string& src_ip, const std::string& dst_ip);

public:
    /**
     * @brief Default destructor.
     */
    ~RuleTree() = default;

    RuleTree(const RuleTree&) = delete;
    RuleTree& operator=(const RuleTree&) = delete;

    /**
     * @brief Returns the singleton instance of the RuleTree.
     * @return Reference to the RuleTree instance.
     */
    static RuleTree& getInstance();

    /**
     * @brief Initializes and builds the rule tree from configuration.
     */
    void buildTree();

    /**
     * @brief Handles outbound packet forwarding based on filtering rules.
     * @param parsed_packet Parsed packet object.
     * @return True if packet is allowed to be forwarded, false if blocked.
     */
    bool handleOutboundForwarding(const pcpp::Packet& parsed_packet);
};

