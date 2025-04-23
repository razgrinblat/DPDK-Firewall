#include "FtpRulesHandler.hpp"

FtpRulesHandler::FtpRulesHandler(): _ftp_rules_parser(FtpRulesParser::getInstance(Config::FTP_RULES_PATH))
{
    _file_watcher.addWatch(Config::FTP_RULES_PATH,std::bind(&FtpRulesHandler::fileEventCallback,this));
    _file_watcher.startWatching();
}

void FtpRulesHandler::fileEventCallback()
{
    std::unique_lock lock(_rules_mutex);
    _ftp_rules_parser.loadRules();
    _ftp_rules_parser.getFtpRules();
}

bool FtpRulesHandler::isValidFileName(const std::string& file_name, const std::unordered_set<std::string>& patterns) const
{
    for (const auto& pattern : patterns)
    {
        if (file_name.find(pattern) != std::string::npos)
        {
            return false;
        }
    }
    return true;
}

FtpRulesHandler & FtpRulesHandler::getInstance()
{
    static FtpRulesHandler instance;
    return instance;
}

void FtpRulesHandler::buildRules()
{
    _ftp_rules_parser.loadRules();
    _http_rule = _ftp_rules_parser.getFtpRules();
    std::cout << "FTP Rules built Successfully!" << std::endl;
}

bool FtpRulesHandler::isValidUploadFileName(const std::string &file_name)
{
    return isValidFileName(file_name, _ftp_rules_parser.getFtpRules().upload_file_names);
}

bool FtpRulesHandler::isValidDownloadFileName(const std::string &file_name)
{
    return isValidFileName(file_name, _ftp_rules_parser.getFtpRules().download_file_names);
}

std::optional<std::string> FtpRulesHandler::allowByUploadFileContent(const std::string &file_content)
{
    return _ftp_rules_parser.getUploadFtpAhoCorasick().search(file_content);
}

std::optional<std::string> FtpRulesHandler::allowByDownloadFileContent(const std::string &file_content)
{
    return _ftp_rules_parser.getDownloadFtpAhoCorasick().search(file_content);
}
