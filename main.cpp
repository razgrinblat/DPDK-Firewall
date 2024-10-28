#include "PacketSniffer.hpp"


int main()
{
    try {
        PacketSniffer();
    }
    catch (const std::exception& e) {
        std::cerr << "Exception:" << e.what()<< std::endl;
    }

    return 0;


}





