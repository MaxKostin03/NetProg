#include <algorithm>
#include <cassert>
#include <filesystem>
#include <fstream>
#include <future>
#include <iostream>
#include <list>
#include <optional>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>
#include <ctime>
#include <boost/system/error_code.hpp>
#include <boost/asio.hpp>

#include <cerrno>

#if !defined(_WIN32)
extern "C"
{
#   include <signal.h>
}
#else
#   include <cwctype>
#endif

#include <socket_wrapper/socket_headers.h>
#include <socket_wrapper/socket_wrapper.h>
#include <socket_wrapper/socket_class.h>

#if !defined(MAX_PATH)
#   define MAX_PATH (256)
#endif

const auto clients_count = 10;
const auto buffer_size = 4096;
using namespace std::literals;
namespace fs = std::filesystem;

#if defined(_WIN32)
const wchar_t separ = fs::path::preferred_separator;
#else
const wchar_t separ = *reinterpret_cast<const wchar_t*>(&fs::path::preferred_separator);
#endif

using boost::asio::ip::tcp;
const int echo_port = 1300;

std::string make_daytime_string()
{
    using namespace std;
    time_t now = time(0);
    return ctime(&now);
}

socket_wrapper::Socket accept_client(socket_wrapper::Socket& server_sock)
{
    struct sockaddr_storage client_addr;
    socklen_t client_addr_length = sizeof(client_addr);
    std::array<char, INET_ADDRSTRLEN> addr;

    socket_wrapper::Socket client_sock(accept(server_sock, reinterpret_cast<sockaddr*>(&client_addr), &client_addr_length));

    if (!client_sock)
    {
        throw std::logic_error("Accepting client");
    }

    assert(sizeof(sockaddr_in) == client_addr_length);

    std::cout <<
        "Client from " << inet_ntop(AF_INET, &(reinterpret_cast<const sockaddr_in* const>(&client_addr)->sin_addr), &addr[0], addr.size())
        << "..."
        << std::endl;
    return client_sock;
}

std::unique_ptr<addrinfo, decltype(&freeaddrinfo)>
get_serv_info(const char* port)
{
    struct addrinfo hints =
    {
        .ai_flags = AI_PASSIVE,
        .ai_family = AF_INET,
        .ai_socktype = SOCK_STREAM,
        .ai_protocol = IPPROTO_TCP
    };
    struct addrinfo* s_i;
    int ai_status;

    if ((ai_status = getaddrinfo(nullptr, port, &hints, &s_i)) != 0)
    {
        std::cerr << "getaddrinfo error " << gai_strerror(ai_status) << std::endl;
        return std::unique_ptr<addrinfo, decltype(&freeaddrinfo)>(nullptr, freeaddrinfo);
    }

    return std::unique_ptr<addrinfo, decltype(&freeaddrinfo)>(s_i, freeaddrinfo);
}

void set_reuse_addr(socket_wrapper::Socket& sock)
{
    const int flag = 1;

    // Allow reuse of port.
    if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, reinterpret_cast<const char*>(&flag), sizeof(flag)) < 0)
    {
        throw std::logic_error("Set SO_REUSEADDR error");
    }
}

class Transceiver
{
public:
    Transceiver(socket_wrapper::Socket&& client_sock) : client_sock_(std::move(client_sock)) {}
    Transceiver(const Transceiver&) = delete;
    Transceiver() = delete;

public:
    const socket_wrapper::Socket& ts_socket() const { return client_sock_; }

public:
    bool send_buffer(const std::vector<char>& buffer)
    {
        size_t transmit_bytes_count = 0;
        const auto size = buffer.size();

        while (transmit_bytes_count != size)
        {
            auto result = send(client_sock_, &(buffer.data()[0]) + transmit_bytes_count, size - transmit_bytes_count, 0);
            if (-1 == result)
            {
                if (need_to_repeat()) continue;
                return false;
            }

            transmit_bytes_count += result;
        }

        return true;
    }

    bool send_file(fs::path const& file_path)
    {
        std::vector<char> buffer(buffer_size);
        std::ifstream file_stream(file_path, std::ifstream::binary);

        if (!file_stream) return false;

        std::cout << "Sending file " << file_path << "..." << std::endl;
        while (file_stream)
        {
            file_stream.read(&buffer[0], buffer.size());
            if (!send_buffer(buffer)) return false;
        }

        return true;
    }

    std::string get_request()
    {
        std::array<char, MAX_PATH + 1> buffer;
        size_t recv_bytes = 0;
        const auto size = buffer.size() - 1;

        std::cout << "Reading user request..." << std::endl;
        while (true)
        {
            auto result = recv(client_sock_, &buffer[recv_bytes], size - recv_bytes, 0);

            if (!result) break;

            if (-1 == result)
            {
                if (need_to_repeat()) continue;
                throw std::logic_error("Socket reading error");
            }

            auto fragment_begin = buffer.begin() + recv_bytes;
            auto ret_iter = std::find_if(fragment_begin, fragment_begin + result,
                [](char sym) { return '\n' == sym || '\r' == sym;  });
            if (ret_iter != buffer.end())
            {
                *ret_iter = '\0';
                recv_bytes += std::distance(fragment_begin, ret_iter);
                break;
            }
            recv_bytes += result;
            if (size == recv_bytes) break;
        }

        buffer[recv_bytes] = '\0';

        auto result = std::string(buffer.begin(), buffer.begin() + recv_bytes);
        std::cout << "Request = \"" << result << "\"" << std::endl;

        return result;
    }

private:
    static bool need_to_repeat()
    {
        switch (errno)
        {
        case EINTR:
        case EAGAIN:
            // case EWOULDBLOCK: // EWOULDBLOCK == EINTR.
            return true;
        }

        return false;
    };

private:
    socket_wrapper::Socket client_sock_;
};

class Client
{
public:
    Client(socket_wrapper::Socket&& sock) :
        tsr_(std::move(sock))
    {
        std::cout
            << "Client [" << static_cast<int>(tsr_.ts_socket()) << "] "
            << "was created..."
            << std::endl;
    }

    std::optional<fs::path> recv_file_path()
    {
        auto request_data = tsr_.get_request();
        if (!request_data.size()) return std::nullopt;

        auto cur_path = fs::current_path().wstring();
        auto file_path = fs::weakly_canonical(request_data).wstring();

#if defined(_WIN32)
        std::transform(cur_path.begin(), cur_path.end(), cur_path.begin(),
            [](wchar_t c) { return std::towlower(c); }
        );
        std::transform(file_path.begin(), file_path.end(), file_path.begin(),
            [](wchar_t c) { return std::towlower(c); }
        );
#endif
        if (file_path.find(cur_path) == 0)
        {
            file_path = file_path.substr(cur_path.length());
        }

        return fs::weakly_canonical(cur_path + separ + file_path);
    }

    bool send_file(const fs::path& file_path)
    {
        if (!(fs::exists(file_path) && fs::is_regular_file(file_path))) return false;

        return tsr_.send_file(file_path);
    }

    bool process()
    {
        auto file_to_send = recv_file_path();
        bool result = false;

        if (std::nullopt != file_to_send)
        {
            std::cout << "Trying to send " << *file_to_send << "..." << std::endl;
            if (send_file(*file_to_send))
            {
                std::cout << "File was sent." << std::endl;
            }
            else
            {
                std::cerr << "File sending error!" << std::endl;
            }
            result = true;
        }

        return result;
    }

private:
    Transceiver tsr_;
    fs::path file_path_;
};

class TcpConnection : public std::enable_shared_from_this<TcpConnection>
{
public:
    typedef std::shared_ptr<TcpConnection> pointer;

    static pointer create(boost::asio::io_context& io_context)
    {
        return pointer(new TcpConnection(io_context));
    }

    tcp::socket& socket()
    {
        return socket_;
    }

    void start()
    {
        message_ = make_daytime_string();
        auto s = shared_from_this();

        boost::asio::async_write(socket_, boost::asio::buffer(message_),
            // handle_write() выполнит обработку запроса клиента.
            [s](const boost::system::error_code& error, size_t bytes_transferred)
            {
                s->handle_write(error, bytes_transferred);
            }
        );
    }

private:
    TcpConnection(boost::asio::io_context& io_context)
        : socket_(io_context)
    {
    }

    void handle_write(const boost::system::error_code& /*error*/, size_t bytes_transferred)
    {
        std::cout << "Bytes transferred: " << bytes_transferred << std::endl;
    }

private:
    tcp::socket socket_;
    std::string message_;
};


class TcpServer
{
public:
    TcpServer(boost::asio::io_context& io_context) :
        io_context_(io_context),
        acceptor_(io_context, tcp::endpoint(tcp::v4(), echo_port))
    {
        start_accept();
    }

private:
    void start_accept()
    {
        TcpConnection::pointer new_connection = TcpConnection::create(io_context_);

        acceptor_.async_accept(new_connection->socket(),
            [this, new_connection](const boost::system::error_code& error)
            {
                this->handle_accept(new_connection, error);
            }
        );
    }

    void handle_accept(TcpConnection::pointer new_connection, const boost::system::error_code& error)
    {
        if (!error)
        {
            new_connection->start();
        }

        start_accept();
    }

private:
    boost::asio::io_context& io_context_;
    tcp::acceptor acceptor_;
};

int main(int argc, const char * const argv[])
{

    if (argc != 2)
    {
        std::cout << "Usage: " << argv[0] << " <port>" << std::endl;
        return EXIT_FAILURE;
    }

#if !defined(_WIN32)
    signal(SIGPIPE, SIG_IGN);
#endif

    socket_wrapper::SocketWrapper sock_wrap;
    
    try
    {
        auto servinfo = get_serv_info(argv[1]);
        if (!servinfo)
        {
            std::cerr << "Can't get servinfo!" << std::endl;
            exit(EXIT_FAILURE);
        }
    
        socket_wrapper::Socket server_sock = { servinfo->ai_family, servinfo->ai_socktype, servinfo->ai_protocol };

    if (!server_sock)
    {
        throw std::logic_error("Socket creation error");
    }

    set_reuse_addr(server_sock);

    if (bind(server_sock, servinfo->ai_addr, servinfo->ai_addrlen) < 0)
    {
        throw std::logic_error("Bind error");
    }

    std::list<std::future<bool>> pending_tasks;

    std::cout
        << "Listening on port " << argv[1] << "...\n"
        << "Server path: " << fs::current_path()
        << std::endl;

    if (listen(server_sock, clients_count) < 0)
    {
        throw std::logic_error("Listen error");
    }

    std::cout << "Listen was run..." << std::endl;

    while (true)
    {
        auto client_sock = accept_client(server_sock);

        if (!client_sock)
        {
            throw std::logic_error("Client socket error");
        }

        pending_tasks.push_back(std::async(std::launch::async, [&](socket_wrapper::Socket&& sock)
            {
                Client client(std::move(sock));
                std::cout << "Client tid = " << std::this_thread::get_id() << std::endl;
                auto result = client.process();
                std::cout
                    << "Client with tid = " << std::this_thread::get_id()
                    << " exiting..."
                    << std::endl;

                return result;
            }, std::move(client_sock)));

        std::cout << "Cleaning tasks..." << std::endl;
        for (auto task = pending_tasks.begin(); task != pending_tasks.end();)
        {
            if (std::future_status::ready == task->wait_for(1ms))
            {
                auto fu = task++;
                std::cout
                    << "Request completed with a result = " << fu->get() << "...\n"
                    << "Removing from list." << std::endl;
                pending_tasks.erase(fu);
            }
            else ++task;
        }
        for (;;)
        {
            tcp::socket spcket(io_context);
            acceptor, accept(socket);
            std::string message = make_daytime_string();
            boost::system::error_code ignored error;
            boost::asio::write(socket, boost::asio::buffer(message), ignored_error);

        }
    }
    catch (const std::logic_error &e)
    {
        std::cerr
            << e.what()
            << " [" << sock_wrap.get_last_error_string() << "]!"
            << std::endl;
        return EXIT_FAILURE
    }
    catch (const std::exception& e)
    {
        std::cerr << e.what() << std::endl;
    }
        
    return EXIT_SUCCESS;
}