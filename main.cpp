#include "PacketSniffer.hpp"

int main()
{
    try {
        PacketSniffer firewall;
        firewall.startingCapture();
    }
    catch (const std::exception& e) {
        std::cerr << "Exception: " << e.what() << std::endl;
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}