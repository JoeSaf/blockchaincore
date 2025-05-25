// asio.hpp - Minimal ASIO compatibility header
#ifndef ASIO_HPP
#define ASIO_HPP

// For build compatibility - replace with proper ASIO installation
// Install real ASIO with: sudo pacman -S asio

#include <memory>
#include <string>
#include <functional>
#include <system_error>
#include <chrono>
#include <thread>

namespace asio {

// Minimal type definitions for compilation
class io_context {
public:
    void run() {}
    void stop() {}
};

namespace ip {
    namespace tcp {
        class socket {
        public:
            socket(io_context&) {}
            bool is_open() const { return false; }
            void close() {}
            void close(std::error_code&) {}
            
            struct endpoint {
                std::string address() const { return "127.0.0.1"; }
                std::string to_string() const { return "127.0.0.1:8333"; }
                uint16_t port() const { return 8333; }
            };
            
            endpoint remote_endpoint() const { return endpoint{}; }
        };
        
        class acceptor {
        public:
            acceptor(io_context&, const tcp::endpoint&) {}
            void set_option(const auto&) {}
            void accept(socket&, std::error_code&) {}
            void close(std::error_code&) {}
        };
        
        class resolver {
        public:
            resolver(io_context&) {}
            auto resolve(const std::string&, const std::string&) {
                return std::vector<tcp::endpoint>{};
            }
        };
        
        class endpoint {
        public:
            endpoint() = default;
            endpoint(const auto&, uint16_t) {}
            std::string address() const { return "127.0.0.1"; }
            uint16_t port() const { return 8333; }
        };
        
        auto v4() { return tcp::endpoint{}; }
    }
}

template<typename T>
auto buffer(T& data) { return data; }

template<typename T>
auto buffer(const T& data) { return data; }

template<typename Socket, typename Buffer>
size_t read(Socket&, Buffer&, std::error_code&) { return 0; }

template<typename Socket, typename Buffer>
size_t write(Socket&, Buffer&, std::error_code&) { return 0; }

template<typename Socket, typename Endpoints>
auto connect(Socket&, Endpoints&, std::error_code&) { return typename Endpoints::value_type{}; }

} // namespace asio

// Warning message
#warning "Using minimal ASIO stub - install real ASIO: sudo pacman -S asio"

#endif // ASIO_HPP