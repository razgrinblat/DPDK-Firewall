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
    disconnect();
    if (_ws_thread.joinable())
    {
        _ws_thread.join();
    }
}

void WebSocketClient::connect()
{
    std::error_code error_code;
    Client::connection_ptr connection = _client.get_connection(_uri, error_code);
    if (error_code)
    {
        throw std::runtime_error("could not create connection to the Server" + error_code.message());
    }
    _connectionHandle = connection->get_handle();
    _client.connect(connection);

    _ws_thread = std::thread(std::bind(&Client::run, &_client)); // start the WebSocket event loop
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
}

void WebSocketClient::onFail(ConnectionHandle hdl) {
    _is_connected = false;
    std::cerr << "WebSocket connection failed." << std::endl;
}

void WebSocketClient::onMessage(ConnectionHandle hdl, Client::message_ptr msg)
{
    std::cout << "Message received: " << msg->get_payload() << std::endl;
}
