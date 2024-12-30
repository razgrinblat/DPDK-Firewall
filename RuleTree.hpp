#pragma once
#include <Packet.h>
#include <unordered_map>
#include <TcpLayer.h>
#include <UdpLayer.h>
#include <IPv4Layer.h>
#include "RulesParser.hpp"
#include "InotifyWrapper.hpp"
#include <mutex>

class RuleTree
{

private:
    struct TreeNode
    {
        std::unordered_map<std::string, std::shared_ptr<TreeNode>> children;
        std::string action; //True - accept, False - block
    };

    std::shared_ptr<TreeNode> _root;
    RulesParser& _rules_parser;
    std::mutex _tree_mutex;
    InotifyWrapper _file_watcher;
    std::unordered_set<Rule> _conflicted_rules;

    RuleTree();

    bool isIpSubset(const std::string& ip1,const std::string& ip2);
    bool isIpConflict(const std::shared_ptr<TreeNode>& protocol_branch, const std::string& dst_ip);
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
    bool handleInboundForwarding(const pcpp::Packet& parsed_packet);

};
