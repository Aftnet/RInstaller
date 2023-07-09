#include <iostream>
#include "asio.hpp"

#include "globals.hpp"

int main()
{
    using asio::ip::tcp;

    try
    {
        asio::io_context io_context;

        tcp::resolver resolver(io_context);
        auto endpoints = resolver.resolve("localhost", std::to_string(rinstaller::common::PORT_NUMBER));

        std::cout << "Connecting to server" << std::endl;
        tcp::socket socket(io_context);
        asio::connect(socket, endpoints);
        std::cout << "Connected" << std::endl;;

        std::array<char, 128> buf;
        asio::error_code error;

        size_t len = socket.read_some(asio::buffer(buf), error);
        std::string response(buf.data());
        std::cout << response << std::endl;

        std::cin.get();
    }
    catch (std::exception& e)
    {
        std::cerr << e.what() << std::endl;
    }

    return 0;
}
