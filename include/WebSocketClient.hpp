#pragma once
#include <websocketpp/client.hpp>
#include <websocketpp/config/asio_client.hpp>
#include <string>

class WebSocketClient
{

public:
    using Client = websocketpp::client<websocketpp::config::asio_client>;
    using ConnectionHdl = websocketpp::connection_hdl;
    using MessagePtr = Client::message_ptr;

    ~WebSocketClient();
    WebSocketClient(const WebSocketClient&) = delete;
    WebSocketClient& operator=(const WebSocketClient&) = delete;
    static WebSocketClient& getInstance();

    void start(const std::string &uri);  // Starts connection in a separate thread
    void stop();                         // Closes connection and stops the loop
    void send(const std::string &message); // Sends a message if connected
    void setOnMessageCallBack(const std::function<void(const std::string&)>& callback);
    void setOnConnectCallBack(const std::function<void()>& callback);

private:
    WebSocketClient();
    void runLoop();  // Handles connection, reconnection, and event loop

    // WebSocket event handlers
    void onOpen(ConnectionHdl hdl);
    void onClose(ConnectionHdl hdl);
    void onFail(ConnectionHdl hdl);
    void onMessage(ConnectionHdl hdl, MessagePtr msg) const;

    Client _client;
    ConnectionHdl _connectionHandle;
    std::function<void(const std::string&)> _onMessageCallback;
    std::function<void()> _onConnectCallBack;
    std::thread _ws_thread;
    std::atomic<bool> _running;
    std::atomic<bool> _is_connected;
    std::string _uri;
    std::mutex _mutex;
};