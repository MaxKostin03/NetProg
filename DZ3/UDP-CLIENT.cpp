#include <chrono>
#include <exception>
#include <iomanip>
#include <iostream>
#include <iterator>
#include <string>
#include <thread>
#include <vector>

#ifdef _WIN32
#   define ioctl ioctlsocket
#else
extern "C"
{
#   include <netinet/tcp.h>
#   include <sys/ioctl.h>
    // #   include <fcntl.h>
}
#endif

#include <socket_wrapper/socket_headers.h>
#include <socket_wrapper/socket_wrapper.h>
#include <socket_wrapper/socket_class.h>



const auto MAX_RECV_BUFFER_SIZE = 256;

bool send_request(socket_wrapper::Socket& sock, const std::string& request)
{
    ssize_t bytes_count = 0;
    size_t req_pos = 0;
    auto const req_buffer = &(request.c_str()[0]);
    auto const req_length = request.length();

    while (true)
    {
        if ((bytes_count = send(sock, req_buffer + req_pos, req_length - req_pos, 0)) < 0)
        {
            if (EINTR == errno) continue;
        }
        else
        {
            if (!bytes_count) break;

            req_pos += bytes_count;

            if (req_pos >= req_length)
            {
                break;
            }
        }
    }

    return true;
}

int getaddrinfo(const char* hostname,
    const char* service,
    const struct addrinfo* hints,
    struct addrinfo** res);

int main(int argc, char * const argv[])
{
    using namespace std::chrono_literals;

    if (argc != 2)
    {
        std::cout << "Usage: " << argv[0] << " <port> " << std::endl;
        return EXIT_FAILURE;
    }

    socket_wrapper::SocketWrapper sock_wrap;
    socket_wrapper::Socket sock = { AF_INET, SOCK_STREAM, IPPROTO_TCP };
    
    const std::string host_name = { argv[1] };

    const int port{ std::stoi(argv[1]) };
    std::cout << "Running sending on the port " << port << "...\n";

    inet_pton(AF_INET, "127.255.255.255", &addr.sin_addr);
    // addr.sin_addr.s_addr = htonl(INADDR_BROADCAST);

    if (!sock)
    {
        std::cerr << sock_wrap.get_last_error_string() << std::endl;
        return EXIT_FAILURE;
    }

    int broadcast = 1;

    if (-1 == setsockopt(sock, SOL_SOCKET, SO_BROADCAST, reinterpret_cast<const char*>(&broadcast), sizeof(broadcast)))
    {
        throw std::runtime_error("setsockopt()");
    }

    if (bind(sock, reinterpret_cast<const sockaddr*>(&addr), sizeof(sockaddr)) == -1)
    {
        std::cerr << sock_wrap.get_last_error_string() << std::endl;
        return EXIT_FAILURE;
    }

    std::string message = { "Test broadcast messaging!" };

    while (true)
    {
        std::cout << "Sending message to broadcast..." << std::endl;
        sendto(sock, message.c_str(), message.length(), 0, reinterpret_cast<const sockaddr*>(&addr), sizeof(sockaddr_in));
        std::cout << "Message was sent..." << std::endl;
        std::this_thread::sleep_for(1s);
    }

    struct sockaddr_in addr = { .sin_family = PF_INET, .sin_port = htons(port) };
    server_addr.sin_addr.s_addr = *reinterpret_cast<const in_addr_t*>(remote_host->h_addr);

    const std::string host_name = { argv[1] };

    const struct hostent* remote_host{ gethostbyname(host_name.c_str()) };

    struct sockaddr_in server_addr =
    {
        .sin_family = AF_INET,
        .sin_port = htons(std::stoi(argv[2]))
    };

    server_addr.sin_addr.s_addr = *reinterpret_cast<const in_addr_t*>(remote_host->h_addr);

    
    const struct hostent* remote_host{ gethostbyname(host_name.c_str()) };

    if (connect(sock, reinterpret_cast<const sockaddr* const>(&server_addr), sizeof(server_addr)) != 0)
    {
        std::cerr << sock_wrap.get_last_error_string() << std::endl;
        return EXIT_FAILURE;
    }

    socket_wrapper::Socket sock = { AF_INET6, SOCK_STREAM, IPPROTO_TCP };

    struct sockaddr_in6 server_addr = { .sa_family = PF_INET6, .sin_port = htons(port) };
    {
        // AF_INET6.
        sa_family_t sin6_family;
        // Номер порта.
        in_port_t sin6_port;
        // Метка потока IPv6.
        uint32_t sin6_flowinfo;
        // Адрес IPv6.
        struct in6_addr sin6_addr;
        // Scope ID (начиная с ядра Linux 2.4).
        uint32_t sin6_scope_id;
    };
    struct in6_addr
    {
        unsigned char s6_addr[16]; /* IPv6 address */
    };

    struct sockaddr_storage
    {
        // Семейство адресов.
        sa_family_t ss_family;
        // Выравнивание, зависящее от реализации.
        char __ss_pad1[_SS_PAD1SIZE];
        int64_t __ss_align;
        char __ss_pad2[_SS_PAD2SIZE];
    };

    if (bind(sock, reinterpret_cast<const sockaddr_storage*>(&addr), sizeof(sockaddr_storage)) == -1)
    {
        std::cerr << sock_wrap.get_last_error_string() << std::endl;
        return EXIT_FAILURE;
    }

    struct sockaddr_in sa;
    struct sockaddr_in6 sa6;
    sa.sin_addr.s_addr = INADDR_ANY; // использовать мой IPv4-адрес.
    sa6.sin6_addr = in6addr_any;

    struct in6_addr ia6 = IN6ADDR_ANY_INIT;

    std::string request;
    std::vector<char> buffer;
    buffer.resize(MAX_RECV_BUFFER_SIZE);

    std::cout << "Connected to \"" << host_name << "\"..." << std::endl;

    const IoctlType flag = 1;

    if (ioctl(sock, FIONBIO, const_cast<IoctlType*>(&flag)) < 0)
    {
        std::cerr << sock_wrap.get_last_error_string() << std::endl;
        return EXIT_FAILURE;
    }

    if (setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, reinterpret_cast<const char*>(&flag), sizeof(flag)) < 0)
    {
        std::cerr << sock_wrap.get_last_error_string() << std::endl;
        return EXIT_FAILURE;
    }

    std::cout << "Waiting for the user input..." << std::endl;

    while (true)
    {
        std::cout << "> " << std::flush;
        if (!std::getline(std::cin, request)) break;

        std::cout
            << "Sending request: \"" << request << "\"..."
            << std::endl;

        request += "\r\n";

        if (!send_request(sock, request))
        {
            std::cerr << sock_wrap.get_last_error_string() << std::endl;
            return EXIT_FAILURE;
        }

        std::cout
            << "Request was sent, reading response..."
            << std::endl;

        std::this_thread::sleep_for(2ms);

        while (true)
        {
            auto recv_bytes = recv(sock, buffer.data(), buffer.size() - 1, 0);

            std::cout
                << recv_bytes
                << " was received..."
                << std::endl;

            if (recv_bytes > 0)
            {
                buffer[recv_bytes] = '\0';
                std::cout << "------------\n" << std::string(buffer.begin(), std::next(buffer.begin(), recv_bytes)) << std::endl;
                continue;
            }
            else if (-1 == recv_bytes)
            {
                if (EINTR == errno) continue;
                if (0 == errno) break;
                break;
            }

            break;
        }
    }
    
    return EXIT_SUCCESS;
}