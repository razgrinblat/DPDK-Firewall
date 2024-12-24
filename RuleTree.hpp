#pragma once
#include <Packet.h>
#include <unordered_map>
#include "RulesParser.hpp"
#include "InotifyWrapper.hpp"
#include <mutex>

class RuleTree
{

private:
    struct TreeNode
    {
        std::unordered_map<std::string,std::shared_ptr<TreeNode>> children;
        std::string action; //True - accept, False - block
    };

    std::shared_ptr<TreeNode> _root;
    RulesParser& _rules_parser;
    std::mutex _tree_mutex;
    InotifyWrapper _file_watcher;

    RuleTree();
    void addRule(const Rule& rule);
    void deleteRule(const Rule& rule);
    void FileEventCallback();

public:
    ~RuleTree() = default;
    RuleTree(const RuleTree&) = delete;
    RuleTree& operator=(const RuleTree&) = delete;
    static RuleTree& getInstance();

    void buildTree();
    bool allowPacket(const std::string& protocol, const std::string& ip, const std::string& port);

};
