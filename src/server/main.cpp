#include <ctime>
#include <iostream>
#include <string>

#include "globals.hpp"
#include "asio.hpp"

int main()
{
    using asio::ip::tcp;

    try
    {
        asio::io_context io_context;

        std::cout << "Awaiting client connection" << std::endl;

        tcp::acceptor acceptor(io_context, tcp::endpoint(tcp::v6(), rinstaller::common::PORT_NUMBER));
        acceptor.set_option(asio::detail::socket_option::integer<SOL_SOCKET, SO_RCVTIMEO>{ 200 });
        tcp::socket socket(io_context);
        acceptor.accept(socket);
        std::cout << "Client connected" << std::endl;

        asio::error_code ignored_error;
        std::cout << "Sending payload" << std::endl;
        asio::write(socket, asio::buffer("Hello there!"), ignored_error);
        std::cout << "Sent" << std::endl;

        std::cin.get();
    }
    catch (std::exception& e)
    {
        std::cerr << e.what() << std::endl;
    }

    return 0;
}
