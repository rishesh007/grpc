#include <grpcpp/grpcpp.h>
#include <grpcpp/security/server_credentials.h>
#include <grpcpp/server.h>
#include <grpcpp/server_builder.h>
#include <grpcpp/server_context.h>

#include <fstream>
#include <iostream>
#include <memory>
#include <sstream>
#include <string>

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

// Implement your service
class GreeterServiceImpl final : public helloworld::Greeter::Service {
  grpc::Status SayHello(grpc::ServerContext* context,
                        const helloworld::HelloRequest* request,
                        helloworld::HelloReply* reply) override {
    std::string prefix("Hello ");
    // You can check client identity if using mTLS:
    // grpc::string peer_identity =
    // context->auth_context()->FindPropertyValues("x509_common_name").front();
    // std::cout << "Got request from: " << peer_identity << std::endl;
    reply->set_message(prefix + request->name());
    return grpc::Status::OK;
  }
};

void RunServer() {
  std::string server_address("0.0.0.0:50051");
  GreeterServiceImpl service;

  // --- TLS Configuration ---
  std::string server_key;
  std::string server_cert;
  std::string root_cert;  // Needed only if requesting client certs (mTLS)

  try {
    server_key = ReadFile("server.key");
    server_cert = ReadFile("server.crt");
    // root_cert = ReadFile("ca.crt"); // Uncomment for mTLS
  } catch (const std::runtime_error& e) {
    std::cerr << "Error reading certificate files: " << e.what() << std::endl;
    return;
  }

  grpc::SslServerCredentialsOptions::PemKeyCertPair pkcp = {server_key,
                                                            server_cert};
  grpc::SslServerCredentialsOptions ssl_opts;
  ssl_opts.pem_key_cert_pairs.push_back(pkcp);

  // --- Optional: Configure Mutual TLS (mTLS) ---
  // If you want the server to require and verify client certificates:
  // ssl_opts.pem_root_certs = root_cert;
  // ssl_opts.client_certificate_request =
  // GRPC_SSL_REQUEST_AND_REQUIRE_CLIENT_CERTIFICATE_AND_VERIFY;
  // --- End mTLS Configuration ---

  std::shared_ptr<grpc::ServerCredentials> server_credentials =
      grpc::SslServerCredentials(ssl_opts);
  // --- End TLS Configuration ---

  grpc::ServerBuilder builder;
  // Listen on the server address using the TLS credentials
  builder.AddListeningPort(server_address, server_credentials);
  builder.RegisterService(&service);

  std::unique_ptr<grpc::Server> server(builder.BuildAndStart());
  if (!server) {
    std::cerr << "Server failed to start on " << server_address << std::endl;
    return;
  }
  std::cout << "Server listening securely on " << server_address << std::endl;
  server->Wait();
}

int main(int argc, char** argv) {
  RunServer();
  return 0;
}