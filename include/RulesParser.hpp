#pragma once
#include <fstream>
#include <json/json.h>
#include <string>

class RulesParser
{
protected:
    std::ifstream _file;
    std::string _file_path;
    Json::Value _root;

public:
    explicit RulesParser(const std::string& file_path);
    virtual ~RulesParser();

    // Shared method for opening and parsing the rules file
    virtual void openAndParseRulesFile() final;

    virtual void loadRules() = 0;
};

