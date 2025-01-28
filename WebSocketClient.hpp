#pragma once
#include <websocketpp/client.hpp>
#include <websocketpp/config/asio_client.hpp>
#include <string>

class WebSocketClient
{

public:
    WebSocketClient(const std::string& uri);
    ~WebSocketClient();

    void setOnMessageCallBack(const std::function<void(const std::string&)>& callback);

    void start();

    void scheduleReconnect(uint16_t delay_seconds);
    // Establish connection to the Node.js server
    void doConnect();

    // Send message to the server
    void sendMessage(const std::string& message);

    // Disconnect from the server
    void disconnect();

    // check if the websocket is connected
    bool isConnected() const;

private:

    typedef websocketpp::client<websocketpp::config::asio_client> Client;
    typedef websocketpp::connection_hdl ConnectionHandle;

    Client _client;
    ConnectionHandle _connectionHandle;
    std::string _uri;
    bool _is_connected;
    std::thread _ws_thread;
    std::function<void(const std::string&)> _onMessageCallback;

    // WebSocket event handlers
    void onOpen(ConnectionHandle hdl);
    void onClose(ConnectionHandle hdl);
    void onFail(ConnectionHandle hdl);
    void onMessage(ConnectionHandle hdl, Client::message_ptr msg);
};