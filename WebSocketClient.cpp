#include "WebSocketClient.hpp"

WebSocketClient::WebSocketClient(const std::string &uri): _uri(uri), _is_connected(false)
{
    _client.init_asio();
    _client.set_open_handler(std::bind(&WebSocketClient::onOpen,this,std::placeholders::_1));
    _client.set_close_handler(std::bind(&WebSocketClient::onClose,this,std::placeholders::_1));
    _client.set_fail_handler(std::bind(&WebSocketClient::onFail,this,std::placeholders::_1));
    _client.set_message_handler(std::bind(&WebSocketClient::onMessage,this,std::placeholders::_1,std::placeholders::_2));
}

WebSocketClient::~WebSocketClient()
{
    _client.stop();
    if (_ws_thread.joinable())
    {
        _ws_thread.join();
    }
}

void WebSocketClient::setOnMessageCallBack(const std::function<void(const std::string &)> &callback)
{
    _onMessageCallback = callback;
}

void WebSocketClient::start()
{
    _ws_thread = std::thread(&Client::run, &_client);
    doConnect();
}

void WebSocketClient::scheduleReconnect(const uint16_t delay_seconds)
{
    _client.set_timer(delay_seconds * 1000, [this](const websocketpp::lib::error_code& ec) {
        if (!ec) {
            doConnect();
        }
    });
}

void WebSocketClient::doConnect()
{
    if (_is_connected)
    {
        return;
    }
    try {
        std::error_code ec;
        const Client::connection_ptr conn = _client.get_connection(_uri, ec);

        if (ec) {
            std::cerr << "[WebSocketClient] Error creating connection: " << ec.message() << std::endl;
            scheduleReconnect(2);  // Retry after 2 seconds
            return;
        }
        _connectionHandle = conn->get_handle();
        _client.connect(conn);

    } catch (const std::exception& e) {
        std::cerr << "[WebSocketClient] Exception during connection: " << e.what() << std::endl;
        scheduleReconnect(2);  // Retry after 2 seconds
    }
}

void WebSocketClient::sendMessage(const std::string &message)
{
    if (_is_connected)
    {
        std::error_code error_code;
        _client.send(_connectionHandle,message,websocketpp::frame::opcode::TEXT,error_code);
        if (error_code)
        {
            std::cerr << "Sending message failed"  << error_code.message() << std::endl;
        }
    }
    else
    {
        std::cerr << "Cannot send message, not connected to server." << std::endl;
    }
}

void WebSocketClient::disconnect()
{
    if (_is_connected)
    {
        std::error_code error_code;
        _client.close(_connectionHandle,websocketpp::close::status::going_away,"Client Disconnected",error_code);
        if (error_code)
        {
            std::cerr << "disconnected failed" << error_code.message() << std::endl;
        }
    }
}

bool WebSocketClient::isConnected() const
{
    return _is_connected;
}

void WebSocketClient::onOpen(ConnectionHandle hdl) {
    _is_connected = true;
    std::cout << "WebSocket connection established." << std::endl;

}

void WebSocketClient::onClose(ConnectionHandle hdl) {
    _is_connected = false;
    std::cout << "WebSocket connection closed." << std::endl;
    scheduleReconnect(2);
}

void WebSocketClient::onFail(ConnectionHandle hdl) {
    _is_connected = false;
    std::cerr << "WebSocket connection failed." << std::endl;
    scheduleReconnect(2);
}

void WebSocketClient::onMessage(ConnectionHandle hdl, Client::message_ptr msg)
{
    std::cout << "Message received: " << msg->get_payload() << std::endl;

    if (_onMessageCallback)
    {
        _onMessageCallback(msg->get_payload());
    }
}
