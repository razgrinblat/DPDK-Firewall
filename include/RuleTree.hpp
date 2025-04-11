#pragma once
#include <Packet.h>
#include <unordered_map>
#include <TcpLayer.h>
#include <UdpLayer.h>
#include <IPv4Layer.h>
#include "IpRulesParser.hpp"
#include "InotifyWrapper.hpp"
#include <shared_mutex>

class RuleTree
{

private:
    struct TreeNode
    {
        std::unordered_map<std::string, std::shared_ptr<TreeNode>> children;
        bool action; //True - accept, False - block
    };

    std::shared_ptr<TreeNode> _root;
    IpRulesParser& _ip_rules_parser;
    std::shared_mutex _tree_mutex; // shared mutex for rules writer thread to acquire an exclusive lock
    InotifyWrapper _file_watcher;
    std::unordered_set<Rule> _conflicted_rules;
    int _generic_ip_number; // number that indicate how much generic ip rules are in the tree (for example *.*.*.8)

    RuleTree();

    bool isIpSubset(const std::string& ip1,const std::string& ip2);
    std::optional<std::string> findIpMatch(const std::shared_ptr<TreeNode>& protocol_branch, const std::string& dst_ip);
    bool isIpConflict(const std::shared_ptr<TreeNode>& protocol_branch, const std::string& dst_ip);
    std::shared_ptr<TreeNode> getChild(const std::shared_ptr<TreeNode>& node, const std::string& key);
    void addRule(const Rule& rule);
    void deleteRule(const Rule& rule);
    void resolveConflictedRules(const std::unordered_set<Rule>& current_rules);
    void deletingRulesEventHandler(const std::unordered_set<Rule>& previous_rules, const std::unordered_set<Rule>& current_rules);
    void insertingRulesEventHandler(const std::unordered_set<Rule>& previous_rules, const std::unordered_set<Rule>& current_rules);
    void FileEventCallback();
    bool isPacketAllowed(const std::string& protocol, const std::string& ip, const std::string& port);

public:
    ~RuleTree() = default;
    RuleTree(const RuleTree&) = delete;
    RuleTree& operator=(const RuleTree&) = delete;
    static RuleTree& getInstance();

    void buildTree();
    bool handleOutboundForwarding(const pcpp::Packet& parsed_packet);
};
