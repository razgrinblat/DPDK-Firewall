#include "WebReceiverHandler.hpp"

WebReceiverHandler & WebReceiverHandler::getInstance()
{
    static WebReceiverHandler instance;
    return instance;
}

void WebReceiverHandler::webMessageCallBack(const std::string& text)
{
    Json::CharReaderBuilder readerBuilder;
    Json::Value root;
    std::string errs;

    std::istringstream ss(text);
    if (!Json::parseFromStream(readerBuilder, ss, &root, &errs))
    {
        throw std::runtime_error("Failed to parse web JSON: " + errs + "\n");
    }
    if (root["type"] == "update rules")
    {
        root.removeMember("type");
        if (root.isMember("rules"))
        {
            //handle ip rules update from the web
            writeRulesToFile(root.toStyledString(),Config::IP_RULES_PATH);
        }
        else if (root.isMember("dpi_rules"))
        {
            //handle DPI rules update from the web
            writeRulesToFile(root.toStyledString(), Config::HTTP_RULES_PATH);
        }
    }
    else {
        std::cerr << "Unknown message from Backend: " << text << std::endl;
    }
}

void WebReceiverHandler::writeRulesToFile(const std::string &ip_rules, const std::string &file_path)
{
    std::ofstream rules_file((file_path.data()));
    if (!rules_file)
    {
        throw std::runtime_error("Failed to open file: " + file_path + "\n");
    }
    rules_file << ip_rules;
    rules_file.close();
}