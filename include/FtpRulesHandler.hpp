#pragma once
#include <shared_mutex>
#include "InotifyWrapper.hpp"
#include "FtpRulesParser.hpp"
#include "Config.hpp"

class FtpRulesHandler
{

private:
    FtpRulesParser& _ftp_rules_parser;
    FtpRulesParser::FtpRule _http_rule;
    InotifyWrapper _file_watcher;
    std::shared_mutex _rules_mutex;

    FtpRulesHandler();
    ~FtpRulesHandler() = default;
    void fileEventCallback();

    bool isValidFileName(const std::string& file_name, const std::unordered_set<std::string>& patterns) const;

public:
    FtpRulesHandler(const FtpRulesHandler&) = delete;
    FtpRulesHandler& operator=(const FtpRulesHandler&) = delete;
    static FtpRulesHandler& getInstance();

    void buildRules();
    bool isValidUploadFileName(const std::string& file_name);
    bool isValidDownloadFileName(const std::string& file_name);
    std::optional<std::string> allowByUploadFileContent(const std::string& file_content);
    std::optional<std::string> allowByDownloadFileContent(const std::string& file_content);

};