#include <iostream>
#include <memory>
#include <string>
#include <fstream>
#include <sstream>

#include <grpcpp/grpcpp.h>
#include <grpcpp/security/credentials.h>
#include <grpcpp/channel.h>
#include <grpcpp/client_context.h>

// Include your generated headers
#include "helloworld.grpc.pb.h"

std::string ReadFile(const std::string& filepath) {
    std::ifstream file(filepath);
    if (!file.is_open()) {
        throw std::runtime_error("Could not open file: " + filepath);
    }
    std::stringstream buffer;
    buffer << file.rdbuf();
    return buffer.str();
}

// Assume ReadFile helper function from above is available

class GreeterClient {
public:
    GreeterClient(std::shared_ptr<grpc::Channel> channel)
        : stub_(helloworld::Greeter::NewStub(channel)) {}

    std::string SayHello(const std::string& user) {
        helloworld::HelloRequest request;
        request.set_name(user);
        helloworld::HelloReply reply;
        grpc::ClientContext context;

        grpc::Status status = stub_->SayHello(&context, request, &reply);

        if (status.ok()) {
            return reply.message();
        } else {
            std::cerr << "RPC failed: (" << status.error_code() << ") "
                      << status.error_message() << std::endl;
            return "RPC failed";
        }
    }

private:
    std::unique_ptr<helloworld::Greeter::Stub> stub_;
};

int main(int argc, char** argv) {
    // Use the actual server address or DNS name used in the server certificate's CN/SAN
    std::string target_str = "localhost:50051";

    // --- TLS Configuration ---
    std::string root_cert;
    std::string client_key;  // Needed only for mTLS
    std::string client_cert; // Needed only for mTLS

    try {
        root_cert = ReadFile("ca.crt"); // Client needs CA to verify the server
        // client_key = ReadFile("client.key");   // Uncomment for mTLS
        // client_cert = ReadFile("client.crt");  // Uncomment for mTLS
    } catch (const std::runtime_error& e) {
        std::cerr << "Error reading certificate files: " << e.what() << std::endl;
        return 1;
    }

    grpc::SslCredentialsOptions ssl_opts;
    ssl_opts.pem_root_certs = root_cert;

    // --- Optional: Configure Mutual TLS (mTLS) ---
    // If the server requires client certificates:
    // ssl_opts.pem_key_cert_pair = {client_key, client_cert};
    // --- End mTLS Configuration ---

    auto channel_credentials = grpc::SslCredentials(ssl_opts);
    // --- End TLS Configuration ---

    // Create a channel using the TLS credentials
    // Note: For server certificate validation to work correctly, the target_str
    // should usually match the Common Name (CN) or a Subject Alternative Name (SAN)
    // in the server's certificate. Use grpc::ChannelArguments to override if needed.
    auto channel = grpc::CreateChannel(target_str, channel_credentials);

    GreeterClient greeter(channel);
    std::string user("world");
    std::string reply = greeter.SayHello(user);
    std::cout << "Greeter received: " << reply << std::endl;

    return 0;
}