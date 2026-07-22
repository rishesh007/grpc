//
// Copyright 2026 gRPC authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//

#include "src/core/filter/ext_proc/ext_proc_filter.h"

#include <grpc/event_engine/event_engine.h>
#include <grpc/impl/channel_arg_names.h>

#include <atomic>
#include <memory>
#include <string>
#include <utility>

#include "src/core/call/call_spine.h"
#include "src/core/call/message.h"
#include "src/core/call/metadata.h"
#include "src/core/client_channel/client_channel_args.h"
#include "src/core/filter/ext_proc/ext_proc_messages.h"
#include "src/core/lib/channel/channel_args.h"
#include "src/core/lib/channel/promise_based_filter.h"
#include "src/core/lib/debug/trace_impl.h"
#include "src/core/lib/promise/if.h"
#include "src/core/lib/promise/inter_activity_latch.h"
#include "src/core/lib/promise/map.h"
#include "src/core/lib/promise/prioritized_race.h"
#include "src/core/lib/promise/seq.h"
#include "src/core/lib/promise/try_join.h"
#include "src/core/lib/promise/try_seq.h"
#include "src/core/lib/resource_quota/arena.h"
#include "src/core/util/down_cast.h"
#include "src/core/util/ref_counted_ptr.h"
#include "src/core/util/time.h"
#include "src/core/xds/grpc/xds_common_types.h"
#include "src/core/xds/xds_client/serialized_streaming_call.h"
#include "src/core/xds/xds_client/xds_bootstrap.h"
#include "src/core/xds/xds_client/xds_transport.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"

namespace grpc_core {

namespace {

const auto kMetricClientExtProcClientHeadersDuration =
    GlobalInstrumentsRegistry::RegisterDoubleHistogram(
        "grpc.client_ext_proc.client_headers_duration",
        "Time between when the ext_proc filter sees the client's headers and "
        "when it allows those headers to continue on to the next filter.",
        "s", false)
        .Labels(kMetricLabelTarget)
        .Build();

const auto kMetricClientExtProcClientHalfCloseDuration =
    GlobalInstrumentsRegistry::RegisterDoubleHistogram(
        "grpc.client_ext_proc.client_half_close_duration",
        "Time between when the ext_proc filter sees the client's half-close "
        "and when it allows that half-close to continue on to the next "
        "filter.",
        "s", false)
        .Labels(kMetricLabelTarget)
        .Build();

const auto kMetricClientExtProcServerHeadersDuration =
    GlobalInstrumentsRegistry::RegisterDoubleHistogram(
        "grpc.client_ext_proc.server_headers_duration",
        "Time between when the ext_proc filter sees the server's headers and "
        "when it allows those headers to continue on to the next filter.",
        "s", false)
        .Labels(kMetricLabelTarget)
        .Build();

const auto kMetricClientExtProcServerTrailersDuration =
    GlobalInstrumentsRegistry::RegisterDoubleHistogram(
        "grpc.client_ext_proc.server_trailers_duration",
        "Time between when the ext_proc filter sees the server's trailers and "
        "when it allows those trailers to continue on to the next filter.",
        "s", false)
        .Labels(kMetricLabelTarget)
        .Build();

}  // namespace

//
// ExtProcFilter::Config
//

std::string ExtProcFilter::Config::ToString() const {
  std::string result = "{";
  bool is_first = true;
  Match(
      channel_info,
      [&](const GrpcXdsServerTarget& target) {
        StrAppend(result, "grpc_service=");
        StrAppend(result, target.Key());
        is_first = false;
      },
      [&](const RefCountedPtr<ExtProcChannel>& channel) {
        if (channel != nullptr) {
          StrAppend(result, "ext_proc_channel=");
          StrAppend(result, channel->server().Key());
          is_first = false;
        }
      });
  if (failure_mode_allow.value_or(false)) {
    if (!is_first) StrAppend(result, ", ");
    StrAppend(result, "failure_mode_allow=true");
    is_first = false;
  }
  if (processing_mode.has_value()) {
    if (!is_first) StrAppend(result, ", ");
    StrAppend(result, "processing_mode=");
    StrAppend(result, processing_mode->ToString());
    is_first = false;
  }
  if (!request_attributes.empty()) {
    if (!is_first) StrAppend(result, ", ");
    StrAppend(result, "request_attributes=[");
    StrAppend(result, absl::StrJoin(request_attributes, ", "));
    StrAppend(result, "]");
    is_first = false;
  }
  if (!response_attributes.empty()) {
    if (!is_first) StrAppend(result, ", ");
    StrAppend(result, "response_attributes=[");
    StrAppend(result, absl::StrJoin(response_attributes, ", "));
    StrAppend(result, "]");
    is_first = false;
  }
  if (mutation_rules.has_value()) {
    if (!is_first) StrAppend(result, ", ");
    StrAppend(result, "mutation_rules=");
    StrAppend(result, mutation_rules->ToString());
    is_first = false;
  }
  if (!forwarding_allowed_headers.empty()) {
    if (!is_first) StrAppend(result, ", ");
    StrAppend(result, "forwarding_allowed_headers=[");
    bool first_matcher = true;
    for (const auto& matcher : forwarding_allowed_headers) {
      if (!first_matcher) StrAppend(result, ", ");
      StrAppend(result, matcher.ToString());
      first_matcher = false;
    }
    StrAppend(result, "]");
    is_first = false;
  }
  if (!forwarding_disallowed_headers.empty()) {
    if (!is_first) StrAppend(result, ", ");
    StrAppend(result, "forwarding_disallowed_headers=[");
    bool first_matcher = true;
    for (const auto& matcher : forwarding_disallowed_headers) {
      if (!first_matcher) StrAppend(result, ", ");
      StrAppend(result, matcher.ToString());
      first_matcher = false;
    }
    StrAppend(result, "]");
    is_first = false;
  }
  if (disable_immediate_response) {
    if (!is_first) StrAppend(result, ", ");
    StrAppend(result, "disable_immediate_response=true");
    is_first = false;
  }
  if (observability_mode) {
    if (!is_first) StrAppend(result, ", ");
    StrAppend(result, "observability_mode=true");
    is_first = false;
  }
  if (deferred_close_timeout != Duration::Zero()) {
    if (!is_first) StrAppend(result, ", ");
    StrAppend(result, "deferred_close_timeout=");
    StrAppend(result, deferred_close_timeout.ToString());
  }
  StrAppend(result, "}");
  return result;
}

bool ExtProcFilter::Config::Equals(const FilterConfig& other) const {
  const auto& o = DownCast<const Config&>(other);
  return channel_info == o.channel_info &&
         failure_mode_allow == o.failure_mode_allow &&
         processing_mode == o.processing_mode &&
         request_attributes == o.request_attributes &&
         response_attributes == o.response_attributes &&
         mutation_rules == o.mutation_rules &&
         forwarding_allowed_headers == o.forwarding_allowed_headers &&
         forwarding_disallowed_headers == o.forwarding_disallowed_headers &&
         disable_immediate_response == o.disable_immediate_response &&
         observability_mode == o.observability_mode &&
         deferred_close_timeout == o.deferred_close_timeout;
}

//
// ExtProcFilter::ExtProcChannel
//

ExtProcFilter::ExtProcChannel::ExtProcChannel(
    std::shared_ptr<const XdsBootstrap::XdsServerTarget> server,
    RefCountedPtr<XdsTransportFactory::XdsTransport> transport)
    : server_(std::move(server)), transport_(std::move(transport)) {
  GRPC_TRACE_LOG(ext_proc_filter, INFO)
      << "creating channel " << this << " for server " << server_->server_uri();
}

ExtProcFilter::ExtProcChannel::~ExtProcChannel() {
  GRPC_TRACE_LOG(ext_proc_filter, INFO)
      << "destroying ext_proc channel " << this << " for server "
      << server_->server_uri();
}
//
// ExtProcFilter::ExtProcCall
//

class ExtProcFilter::ExtProcCall final : public DualRefCounted<ExtProcCall> {
 public:
  ExtProcCall(RefCountedPtr<XdsTransportFactory::XdsTransport> transport,
              RefCountedPtr<const Config> config,
              std::shared_ptr<grpc_event_engine::experimental::EventEngine>
                  event_engine)
      : config_(std::move(config)),
        transport_(std::move(transport)),
        event_engine_(std::move(event_engine)) {
    const char* method = "/envoy.service.ext_proc.v3.ExternalProcessor/Process";
    streaming_call_ = MakeRefCounted<StreamingCallPromiseWrapper>(
        *transport_, method, std::make_unique<StreamEventHandler>(WeakRef()),
        /*wait_for_ready=*/false);
    streaming_call_->StartRecvMessage();
  }

  ~ExtProcCall() override {
    if (config_->deferred_close_timeout != Duration::Zero() &&
        config_->observability_mode) {
      if (event_engine_ != nullptr) {
        event_engine_->RunAfter(config_->deferred_close_timeout,
                                [call = std::move(streaming_call_),
                                 transport = std::move(transport_)]() mutable {
                                  call.reset();
                                  transport.reset();
                                });
      }
    } else {
      streaming_call_.reset();
    }
  }

  InterActivityLatch<absl::StatusOr<ExtProcResponse>>& request_headers_latch() {
    return request_headers_latch_;
  }

  InterActivityLatch<absl::StatusOr<ExtProcResponse>>&
  response_headers_latch() {
    return response_headers_latch_;
  }

  InterActivityLatch<absl::StatusOr<ExtProcResponse>>&
  response_trailers_latch() {
    return response_trailers_latch_;
  }

  InterActivityPipe<absl::StatusOr<ExtProcResponse>, 16>& request_body_pipe() {
    return request_body_pipe_;
  }

  InterActivityPipe<absl::StatusOr<ExtProcResponse>, 16>& response_body_pipe() {
    return response_body_pipe_;
  }

  RefCountedPtr<const Config> config() const { return config_; }

  bool IsFirstMessageOnStream() {
    return is_first_message_on_ext_proc_stream_.exchange(
        false, std::memory_order_acq_rel);
  }

  bool IsFailOpenAllowed() const {
    const bool allow = config_->failure_mode_allow.value_or(false);
    if (config_->observability_mode) return allow;
    return allow && !first_body_message_sent_.load(std::memory_order_acquire);
  }

  void MarkClientHalfCloseInitiated() {
    c2s_half_close_initiated_.store(true, std::memory_order_release);
  }

  bool IsStreamClosed() const {
    MutexLock lock(&mu_);
    return stream_status_value_.has_value();
  }

  bool ext_proc_stream_half_closed() const {
    return ext_proc_stream_half_closed_.load(std::memory_order_acquire);
  }

  bool drain_requested() const {
    return drain_requested_.load(std::memory_order_acquire);
  }

  void SetDrainRequested() {
    drain_requested_.store(true, std::memory_order_release);
  }

  bool IsStreamClosedCleanly() const {
    MutexLock lock(&mu_);
    return stream_status_value_.has_value() && stream_status_value_->ok();
  }

  void IncrementOutstandingServerToClientMessages() {
    MutexLock lock(&mu_);
    outstanding_s2c_messages_++;
  }

  bool HasOutstandingServerToClientMessages() const {
    MutexLock lock(&mu_);
    return outstanding_s2c_messages_ > 0;
  }

  bool DecrementOutstandingServerToClientMessages(bool* should_close) {
    MutexLock lock(&mu_);
    if (outstanding_s2c_messages_ == 0) {
      return false;
    }
    outstanding_s2c_messages_--;
    if (s2c_writes_done_.load(std::memory_order_acquire) &&
        outstanding_s2c_messages_ == 0) {
      *should_close = true;
    }
    return true;
  }

  void IncrementOutstandingClientToServerMessages() {
    MutexLock lock(&mu_);
    outstanding_c2s_messages_++;
  }

  bool DecrementOutstandingClientToServerMessages() {
    MutexLock lock(&mu_);
    if (outstanding_c2s_messages_ == 0) {
      return false;
    }
    outstanding_c2s_messages_--;
    return true;
  }

  void SetServerToClientWritesDone() {
    s2c_writes_done_.store(true, std::memory_order_release);
    MutexLock lock(&mu_);
    if (outstanding_s2c_messages_ == 0) {
      if (!response_body_pipe_.sender.IsClosed()) {
        response_body_pipe_.sender.MarkClosed();
      }
    }
  }

  void SetIsTrailersOnly() {
    is_trailers_only_.store(true, std::memory_order_release);
  }

  bool is_trailers_only() const {
    return is_trailers_only_.load(std::memory_order_acquire);
  }

  void SetServerTrailersSent() {
    server_trailers_sent_.store(true, std::memory_order_release);
  }

  bool server_trailers_sent() const {
    return server_trailers_sent_.load(std::memory_order_acquire);
  }

  void SetExtProcSetEos() {
    ext_proc_set_eos_.store(true, std::memory_order_release);
  }

  bool ext_proc_set_eos() const {
    return ext_proc_set_eos_.load(std::memory_order_acquire);
  }

  void SetClientSendsDone() {
    c2s_writes_done_.store(true, std::memory_order_release);
  }

  bool c2s_write_done() const {
    return c2s_writes_done_.load(std::memory_order_acquire);
  }

  absl::Status GetStreamStatus() const {
    MutexLock lock(&mu_);
    return stream_status_value_.value_or(absl::OkStatus());
  }

  auto WaitForStreamStatus() {
    return [this]() -> Poll<absl::Status> {
      {
        MutexLock lock(&mu_);
        if (stream_status_value_.has_value()) {
          return *stream_status_value_;
        }
      }
      auto poll = stream_status_.Wait()();
      if (poll.ready()) {
        MutexLock lock(&mu_);
        return stream_status_value_.value_or(absl::OkStatus());
      }
      return Pending{};
    };
  }

  void SetFirstBodyMessageSent() {
    first_body_message_sent_.store(true, std::memory_order_release);
  }

  absl::AnyInvocable<Poll<absl::Status>()> SendMessage(
      absl::AnyInvocable<absl::StatusOr<std::string>()> payload_generator) {
    MutexLock lock(&mu_);
    if (stream_status_value_.has_value() || streaming_call_ == nullptr) {
      return []() -> Poll<absl::Status> {
        return absl::CancelledError("Stream closed");
      };
    }
    auto payload = payload_generator();
    if (!payload.ok()) {
      return [status = payload.status()]() -> Poll<absl::Status> {
        return status;
      };
    }
    return streaming_call_->Send(std::move(*payload));
  }

  void SetStreamError(absl::Status status) {
    SetStreamStatus(status);
    CompleteAllLatchesAndPipes(status);
    CloseStream();
  }

  void CloseStream() {
    RefCountedPtr<StreamingCallPromiseWrapper> streaming_call;
    {
      MutexLock lock(&mu_);
      if (!stream_status_value_.has_value()) {
        stream_status_value_ = absl::OkStatus();
        stream_status_.Set();
      }
      streaming_call = std::move(streaming_call_);
    }
    streaming_call.reset();
    if (!request_body_pipe_.sender.IsClosed()) {
      request_body_pipe_.sender.MarkClosed();
    }
    if (!response_body_pipe_.sender.IsClosed()) {
      response_body_pipe_.sender.MarkClosed();
    }
  }

  auto SendClientInitialMetadataRequest(
      std::shared_ptr<ClientMetadataHandle> metadata,
      absl::string_view default_authority) {
    const bool is_first_message = IsFirstMessageOnStream();
    return SendMessage([config = config_, metadata,
                        default_authority = std::string(default_authority),
                        is_first_message]() {
      GRPC_TRACE_LOG(ext_proc_filter, INFO)
          << "ExtProc: Sending client initial metadata";
      upb::Arena arena;
      auto* header_attributes = CreateExtProcAttributesProtoStruct(
          arena.ptr(), config->request_attributes, **metadata,
          default_authority);
      std::optional<ExtProcProcessingMode> processing_mode;
      if (is_first_message) {
        processing_mode = config->processing_mode;
      }
      return CreateExtProcClientHeadersRequest(
          arena.ptr(), metadata->get(), config->forwarding_allowed_headers,
          config->forwarding_disallowed_headers, header_attributes,
          config->observability_mode, processing_mode);
    });
  }

  auto SendServerInitialMetadataRequest(
      std::shared_ptr<ServerMetadataHandle> metadata,
      bool end_of_stream = false) {
    const bool is_first_message = IsFirstMessageOnStream();
    return SendMessage(
        [config = config_, metadata, is_first_message, end_of_stream]() {
          std::optional<ExtProcProcessingMode> processing_mode;
          if (is_first_message) {
            processing_mode = config->processing_mode;
          }
          upb::Arena arena;
          return CreateExtProcServerHeadersRequest(
              arena.ptr(), metadata->get(), config->forwarding_allowed_headers,
              config->forwarding_disallowed_headers,
              /*attributes=*/nullptr, config->observability_mode,
              processing_mode, end_of_stream);
        });
  }

  auto SendServerMessageRequest(const MessageHandle& message) {
    if (!config_->observability_mode) {
      IncrementOutstandingServerToClientMessages();
    }
    std::string message_bytes;
    if (message != nullptr) {
      message_bytes = message->payload()->JoinIntoString();
    }
    bool is_first_message = IsFirstMessageOnStream();
    return Map(
        SendMessage([ext_proc_call = Ref(), is_first_message,
                     message_bytes = std::move(message_bytes)]() mutable {
          GRPC_TRACE_LOG(ext_proc_filter, INFO)
              << "ExtProc: ServerToClientMessages body message intercepted";
          std::optional<ExtProcProcessingMode> processing_mode;
          if (is_first_message) {
            processing_mode = ext_proc_call->config()->processing_mode;
          }
          upb::Arena arena;
          return CreateExtProcServerBodyRequest(
              arena.ptr(), message_bytes, /*attributes=*/nullptr,
              ext_proc_call->config()->observability_mode, processing_mode);
        }),
        [ext_proc_call = Ref()](absl::Status status) {
          if (status.ok()) {
            ext_proc_call->SetFirstBodyMessageSent();
          }
          return status;
        });
  }

  auto SendServerTrailingMetadataRequest(
      std::shared_ptr<ServerMetadataHandle> metadata) {
    return Map(
        If(
            !IsStreamClosed() && !ext_proc_stream_half_closed(),
            [this, metadata]() {
              const bool is_first_message = IsFirstMessageOnStream();
              return SendMessage([ext_proc_call = Ref(), metadata,
                                  is_first_message]() {
                GRPC_TRACE_LOG(ext_proc_filter, INFO)
                    << "ExtProc: Sending server trailing metadata";
                std::optional<ExtProcProcessingMode> processing_mode;
                if (is_first_message) {
                  processing_mode = ext_proc_call->config()->processing_mode;
                }
                upb::Arena arena;
                return CreateExtProcServerTrailersRequest(
                    arena.ptr(), metadata->get(),
                    ext_proc_call->config()->forwarding_allowed_headers,
                    ext_proc_call->config()->forwarding_disallowed_headers,
                    /*attributes=*/nullptr,
                    ext_proc_call->config()->observability_mode,
                    processing_mode);
              });
            },
            []() -> Poll<absl::Status> { return absl::OkStatus(); }),
        [ext_proc_call = Ref()](absl::Status status) {
          if (status.ok()) {
            ext_proc_call->SetServerTrailersSent();
          }
          return status;
        });
  }

  auto SendClientMessageRequest(const MessageHandle& message,
                                bool end_of_stream,
                                bool end_of_stream_without_message,
                                ::google_protobuf_Struct* attributes) {
    std::string message_bytes;
    if (message != nullptr) {
      message_bytes = message->payload()->JoinIntoString();
    }
    if (!config_->observability_mode) {
      IncrementOutstandingClientToServerMessages();
    }
    if (end_of_stream_without_message) {
      MarkClientHalfCloseInitiated();
    }
    const bool is_first_message = IsFirstMessageOnStream();
    return Map(
        SendMessage([ext_proc_call = Ref(),
                     message_bytes = std::move(message_bytes), end_of_stream,
                     end_of_stream_without_message, attributes,
                     is_first_message]() mutable {
          GRPC_TRACE_LOG(ext_proc_filter, INFO)
              << "ExtProc: ClientToServerMessages body message intercepted "
                 "(observability mode)";
          std::optional<ExtProcProcessingMode> processing_mode;
          if (is_first_message) {
            processing_mode = ext_proc_call->config()->processing_mode;
          }
          upb::Arena arena;
          return CreateExtProcClientBodyRequest(
              arena.ptr(), message_bytes, attributes,
              ext_proc_call->config()->observability_mode, processing_mode,
              end_of_stream, end_of_stream_without_message);
        }),
        [ext_proc_call = Ref()](absl::Status status) {
          if (status.ok()) {
            ext_proc_call->SetFirstBodyMessageSent();
          }
          return status;
        });
  }

 private:
  // Event handler callback for the ext_proc stream. Wraps a weak reference to
  // ExtProcCall to safely dispatch asynchronous stream lifecycle events
  // (message sent, message received, stream closed/status received) back to the
  // owning ExtProcCall instance without preventing destruction or causing
  // cyclic reference memory leaks.
  class StreamEventHandler final
      : public XdsTransportFactory::XdsTransport::StreamingCall::EventHandler {
   public:
    explicit StreamEventHandler(WeakRefCountedPtr<ExtProcCall> call)
        : call_(std::move(call)) {}

    void OnRequestSent(bool ok) override { call_->OnRequestSent(ok); }

    void OnRecvMessage(absl::string_view payload) override {
      call_->OnRecvMessage(payload);
    }

    void OnStatusReceived(absl::Status status) override {
      call_->OnStatusReceived(std::move(status));
    }

   private:
    WeakRefCountedPtr<ExtProcCall> call_;
  };

  void CompleteAllLatchesAndPipes(absl::StatusOr<ExtProcResponse> response) {
    const auto& processing_mode = *config_->processing_mode;
    if (processing_mode.send_request_headers &&
        !request_headers_latch_.IsSet()) {
      request_headers_latch_.Set(response);
    }
    if (processing_mode.send_response_headers &&
        !response_headers_latch_.IsSet()) {
      response_headers_latch_.Set(response);
    }
    if (processing_mode.send_response_trailers &&
        !response_trailers_latch_.IsSet()) {
      response_trailers_latch_.Set(response);
    }
    if (processing_mode.send_request_body &&
        !request_body_pipe_.sender.IsClosed()) {
      if (!response.ok()) {
        request_body_pipe_.sender.Push(response.status())();
      }
      request_body_pipe_.sender.MarkClosed();
    }
    if (processing_mode.send_response_body &&
        !response_body_pipe_.sender.IsClosed()) {
      if (!response.ok()) {
        response_body_pipe_.sender.Push(response.status())();
      }
      response_body_pipe_.sender.MarkClosed();
    }
  }

  void SetStreamStatus(absl::Status status) {
    MutexLock lock(&mu_);
    if (!stream_status_value_.has_value()) {
      stream_status_value_ = status;
      stream_status_.Set();
    }
  }

  void OnRequestSent(bool ok) {}

  void OnRecvMessage(absl::string_view payload) {
    // In observability mode, we only log the message and ignore it.
    // We must continue reading the stream to keep it alive.
    if (config_->observability_mode) {
      GRPC_TRACE_LOG(ext_proc_filter, INFO)
          << "ExtProcCall " << this
          << " message received in observability mode (ignored), size="
          << payload.size();
      MutexLock lock(&mu_);
      if (streaming_call_ != nullptr) {
        streaming_call_->StartRecvMessage();
      }
      return;
    }
    GRPC_TRACE_LOG(ext_proc_filter, INFO)
        << "ExtProcCall " << this
        << " message received, size=" << payload.size();
    // Parse the response from the external processor.
    auto parsed_response = ExtProcResponse::Parse(payload);
    if (!parsed_response.ok()) {
      // If parsing fails, we either fail the stream or close it cleanly
      // (fail-open) depending on configuration.
      if (!IsFailOpenAllowed()) {
        SetStreamError(parsed_response.status());
      } else {
        CompleteAllLatchesAndPipes(ExtProcResponse{});
        CloseStream();
      }
      return;
    }
    // If the server requests a drain, we half-close the stream to signal
    // we are done sending requests.
    if ((*parsed_response).request_drain) {
      GRPC_TRACE_LOG(ext_proc_filter, INFO)
          << "ExtProcCall " << this << " received request_drain=true";
      SetDrainRequested();
      ext_proc_stream_half_closed_.store(true, std::memory_order_release);
      {
        MutexLock lock(&mu_);
        if (streaming_call_ != nullptr) {
          GRPC_TRACE_LOG(ext_proc_filter, INFO)
              << "ExtProcCall " << this << " sending half-close";
          streaming_call_->SendHalfClose();
        }
      }
    }
    // Dispatch the parsed response to the appropriate latch based on the
    // response type.
    const auto& processing_mode = *config_->processing_mode;
    Match(
        (*parsed_response).response,
        [&](const ExtProcResponse::ImmediateResponse&) {
          if (config_->disable_immediate_response || !server_trailers_sent()) {
            auto error = absl::InternalError(
                config_->disable_immediate_response
                    ? "unhandled immediate response due to config disabled it"
                    : "Immediate response received but trailers not sent to "
                      "ext_proc");
            SetStreamError(error);
            return;
          }
          if (processing_mode.send_response_trailers &&
              !response_trailers_latch_.IsSet()) {
            response_trailers_latch_.Set(std::move(*parsed_response));
          }
        },
        [&](const ExtProcResponse::RequestHeaders&) {
          if (!processing_mode.send_request_headers) {
            SetStreamError(
                absl::InternalError("Received request headers response but "
                                    "request headers are disabled"));
            return;
          }
          if (processing_mode.send_request_headers &&
              !request_headers_latch_.IsSet()) {
            request_headers_latch_.Set(std::move(*parsed_response));
          }
        },
        [&](const ExtProcResponse::ResponseHeaders&) {
          if (!processing_mode.send_response_headers) {
            SetStreamError(
                absl::InternalError("Received response headers response but "
                                    "response headers are disabled"));
            return;
          }
          if (processing_mode.send_response_headers &&
              !response_headers_latch_.IsSet()) {
            response_headers_latch_.Set(std::move(*parsed_response));
          }
        },
        [&](const ExtProcResponse::ResponseTrailers&) {
          if (!processing_mode.send_response_trailers) {
            SetStreamError(
                absl::InternalError("Received response trailers response but "
                                    "response trailers are disabled"));
            return;
          }
          if (is_trailers_only()) {
            SetStreamError(absl::InternalError(
                "Received response trailers response in a Trailers-Only call"));
            return;
          }
          if (processing_mode.send_response_headers &&
              !response_headers_latch_.IsSet()) {
            SetStreamError(absl::InternalError(
                "Received response trailers response before "
                "response headers response"));
            return;
          }
          bool s2c_body_outstanding = false;
          {
            MutexLock lock(&mu_);
            if (processing_mode.send_response_body &&
                outstanding_s2c_messages_ > 0) {
              s2c_body_outstanding = true;
            }
          }
          if (s2c_body_outstanding) {
            SetStreamError(absl::InternalError(
                "Received response trailers response before all "
                "outstanding response body responses were received"));
            return;
          }
          if (processing_mode.send_response_trailers &&
              !response_trailers_latch_.IsSet()) {
            response_trailers_latch_.Set(std::move(*parsed_response));
          }
        },
        [&](const ExtProcResponse::RequestBody& request_body) {
          if (!processing_mode.send_request_body) {
            SetStreamError(absl::InternalError(
                "Received request body response but request body is disabled"));
            return;
          }
          if (processing_mode.send_request_headers &&
              !request_headers_latch_.IsSet()) {
            SetStreamError(
                absl::InternalError("Received request body response before "
                                    "request headers response"));
            return;
          }
          if (!DecrementOutstandingClientToServerMessages()) {
            SetStreamError(absl::InternalError(
                "Received unexpected request body response from "
                "external processor"));
            return;
          }
          GRPC_TRACE_LOG(ext_proc_filter, INFO)
              << "ExtProc: Parsed request body response, eos: "
              << request_body.mutation.end_of_stream << ", eos_without_msg: "
              << request_body.mutation.end_of_stream_without_message;
          if (request_body.mutation.end_of_stream_without_message) {
            if (!c2s_write_done()) {
              SetStreamError(absl::InternalError(
                  "Client sends closed by external processor"));
              return;
            }
            SetExtProcSetEos();
            if (!request_body_pipe_.sender.IsClosed()) {
              request_body_pipe_.sender.MarkClosed();
            }
            return;
          }
          bool end_of_stream = request_body.mutation.end_of_stream;
          request_body_pipe_.sender.Push(std::move(*parsed_response))();
          if (end_of_stream) {
            SetExtProcSetEos();
            if (!request_body_pipe_.sender.IsClosed()) {
              request_body_pipe_.sender.MarkClosed();
            }
          }
        },
        [&](const ExtProcResponse::ResponseBody&) {
          if (!processing_mode.send_response_body) {
            SetStreamError(
                absl::InternalError("Received response body response but "
                                    "response body is disabled"));
            return;
          }
          if (is_trailers_only()) {
            SetStreamError(absl::InternalError(
                "Received response body response in a Trailers-Only call"));
            return;
          }
          if (processing_mode.send_response_headers &&
              !response_headers_latch_.IsSet()) {
            SetStreamError(
                absl::InternalError("Received response body response before "
                                    "response headers response"));
            return;
          }
          if (processing_mode.send_response_trailers &&
              response_trailers_latch_.IsSet()) {
            SetStreamError(absl::InternalError(
                "Received response body response after response "
                "trailers response"));
            return;
          }
          if (!HasOutstandingServerToClientMessages()) {
            SetStreamError(absl::InternalError(
                "Received unexpected response body response from "
                "external processor"));
            return;
          }
          // Push the message to the pipe BEFORE decrementing the outstanding
          // count. This prevents a race where SetServerToClientWritesDone()
          // runs concurrently, sees the outstanding count is 0, and closes the
          // pipe before we can push this last message.
          response_body_pipe_.sender.Push(std::move(*parsed_response))();
          bool should_close = false;
          DecrementOutstandingServerToClientMessages(&should_close);
          if (should_close) {
            // If writes are done and this was the last outstanding message, we
            // can close the pipe early to signal completion to the read loop.
            if (!response_body_pipe_.sender.IsClosed()) {
              response_body_pipe_.sender.MarkClosed();
            }
          }
        },
        [](std::monostate) {});
    MutexLock lock(&mu_);
    if (streaming_call_ != nullptr) {
      streaming_call_->StartRecvMessage();
    }
  }

  void OnStatusReceived(absl::Status status) {
    GRPC_TRACE_LOG(ext_proc_filter, INFO)
        << "ExtProcCall " << this << " status received: " << status;
    bool has_outstanding_messages = false;
    {
      MutexLock lock(&mu_);
      has_outstanding_messages =
          outstanding_c2s_messages_ > 0 || outstanding_s2c_messages_ > 0;
    }
    const bool must_drain = !config_->observability_mode &&
                            (config_->processing_mode->send_request_body ||
                             config_->processing_mode->send_response_body);
    const bool drain_requested =
        drain_requested_.load(std::memory_order_relaxed);
    if (status.ok()) {
      if (must_drain && !drain_requested) {
        status = absl::InternalError("Stream closed cleanly without drain");
      } else if (has_outstanding_messages && !config_->observability_mode) {
        status = absl::InternalError(
            "Stream closed cleanly with outstanding messages");
      }
    }
    const bool should_propagate_error = !status.ok() && !IsFailOpenAllowed();
    bool already_closed = false;
    {
      MutexLock lock(&mu_);
      already_closed = stream_status_value_.has_value();
      if (!already_closed) {
        stream_status_value_ = status;
        stream_status_.Set();
      }
    }
    // Always complete latches on status received to avoid hangs.
    if (should_propagate_error) {
      CompleteAllLatchesAndPipes(status);
    } else {
      CompleteAllLatchesAndPipes(ExtProcResponse{});
    }
    if (!already_closed) {
      CloseStream();
    }
  }

  void Orphaned() override { CloseStream(); }

  InterActivityLatch<absl::StatusOr<ExtProcResponse>> request_headers_latch_;
  InterActivityLatch<absl::StatusOr<ExtProcResponse>> response_headers_latch_;
  InterActivityLatch<absl::StatusOr<ExtProcResponse>> response_trailers_latch_;
  InterActivityPipe<absl::StatusOr<ExtProcResponse>, 16> request_body_pipe_;
  InterActivityPipe<absl::StatusOr<ExtProcResponse>, 16> response_body_pipe_;
  RefCountedPtr<const Config> config_;
  // Indicates whether a stream drain operation has been requested by the
  // filter.
  std::atomic<bool> drain_requested_{false};
  // True if no messages have been sent on the external processor stream yet.
  // Used to include overall processing_mode in the initial stream header
  // request.
  std::atomic<bool> is_first_message_on_ext_proc_stream_{true};
  // Tracks whether the first body message has been sent on the stream,
  // used for fail-open determination.
  std::atomic<bool> first_body_message_sent_{false};
  // TODO(rishesh): Need to remove this once PH2 work is done.
  // Number of messages sent to ext_proc that are awaiting response processing
  // in S2C and C2S directions respectively.
  size_t outstanding_s2c_messages_ ABSL_GUARDED_BY(&mu_) = 0;
  size_t outstanding_c2s_messages_ ABSL_GUARDED_BY(&mu_) = 0;
  // Stream state flags tracking directional write completion, half-close,
  // trailers-only RPC mode, and server trailers transmission.
  std::atomic<bool> c2s_writes_done_{false};
  std::atomic<bool> s2c_writes_done_{false};
  std::atomic<bool> c2s_half_close_initiated_{false};
  std::atomic<bool> is_trailers_only_{false};
  std::atomic<bool> server_trailers_sent_{false};
  // Set by external processor server when it requests end of stream (EOS).
  std::atomic<bool> ext_proc_set_eos_{false};
  // Indicates that the external processor stream has been half closed.
  std::atomic<bool> ext_proc_stream_half_closed_{false};
  InterActivityLatch<void> stream_status_;
  std::optional<absl::Status> stream_status_value_ ABSL_GUARDED_BY(mu_);

  mutable Mutex mu_;

  RefCountedPtr<XdsTransportFactory::XdsTransport> transport_;
  std::shared_ptr<grpc_event_engine::experimental::EventEngine> event_engine_;
  RefCountedPtr<StreamingCallPromiseWrapper> streaming_call_;
};

namespace {

bool IsProcessingEnabled(
    const std::optional<ExtProcFilter::ProcessingMode>& processing_mode) {
  if (!processing_mode.has_value()) return false;
  return processing_mode->send_request_headers ||
         processing_mode->send_response_headers ||
         processing_mode->send_response_trailers ||
         processing_mode->send_request_body ||
         processing_mode->send_response_body;
}

absl::Status ApplyHeaderMutations(
    const ExtProcResponse::HeaderMutation& mutations,
    const HeaderMutationRules* rules, grpc_metadata_batch& metadata) {
  for (const auto& remove : mutations.remove_headers) {
    auto status = ApplyXdsHeaderMutationsRemoval(remove, rules, metadata);
    if (!status.ok()) {
      return status;
    }
  }
  for (const auto& add : mutations.set_headers) {
    auto status = ApplyXdsHeaderMutationsAddition(add, rules, metadata);
    if (!status.ok()) {
      return status;
    }
  }
  return absl::OkStatus();
}

template <typename PushFn>
absl::AnyInvocable<Poll<absl::Status>()> SendAndProcessServerHeadersNormalMode(
    RefCountedPtr<ExtProcFilter::ExtProcCall> ext_proc_call,
    std::shared_ptr<ServerMetadataHandle> metadata, bool end_of_stream,
    PushFn push_fn) {
  return Seq(
      ext_proc_call->SendServerInitialMetadataRequest(metadata, end_of_stream),
      [ext_proc_call, metadata,
       push_fn = std::move(push_fn)](absl::Status status) mutable
          -> absl::AnyInvocable<Poll<absl::Status>()> {
        // Handle failure to write the server metadata to the external
        // processor.
        if (!status.ok()) {
          // If the write fails but fail-open behavior is allowed, propagate the
          // metadata downstream unmutated and bypass waiting for a response.
          if (ext_proc_call->IsFailOpenAllowed()) {
            GRPC_TRACE_LOG(ext_proc_filter, INFO)
                << "ExtProc: Server initial metadata send failed, but "
                   "fail-open is allowed. Error: "
                << status;
            push_fn(std::move(*metadata));
            return []() -> Poll<absl::Status> { return absl::OkStatus(); };
          }
          // If fail-open is disabled, fail the RPC with the closed stream error
          // status.
          absl::Status err = ext_proc_call->IsStreamClosed()
                                 ? ext_proc_call->GetStreamStatus()
                                 : status;
          return [err]() -> Poll<absl::Status> { return err; };
        }
        return Map(
            // Wait for response headers (which will contain the external
            // processor's decision on our ServerHeaders request).
            ext_proc_call->response_headers_latch().Wait(),
            [metadata, ext_proc_call, push_fn = std::move(push_fn)](
                absl::StatusOr<ExtProcResponse> response) mutable
                -> absl::Status {
              absl::Status status = absl::OkStatus();
              if (!response.ok()) {
                status = response.status();
              } else if (const auto* headers =
                             std::get_if<ExtProcResponse::ResponseHeaders>(
                                 &response->response);
                         headers != nullptr) {
                const auto* rules =
                    ext_proc_call->config()->mutation_rules.has_value()
                        ? &ext_proc_call->config()->mutation_rules.value()
                        : nullptr;
                // Apply header mutations from the external processor's
                // response.
                status =
                    ApplyHeaderMutations(headers->mutation, rules, **metadata);
              }
              // If an error occurred while waiting for or processing the
              // response, check failure mode configuration. Unless fail-open
              // is allowed, fail the stream with error status.
              if (!status.ok() && !ext_proc_call->IsFailOpenAllowed()) {
                return ext_proc_call->IsStreamClosed()
                           ? ext_proc_call->GetStreamStatus()
                           : status;
              }
              GRPC_TRACE_LOG(ext_proc_filter, INFO)
                  << "ExtProc: Pushing server headers downstream";
              // Push the final (mutated or unmutated) server metadata
              // downstream.
              push_fn(std::move(*metadata));
              return absl::OkStatus();
            });
      });
}

absl::AnyInvocable<Poll<absl::Status>()> ServerInitialMetadataNormalMode(
    CallHandler handler, CallInitiator initiator,
    RefCountedPtr<ExtProcFilter> ext_proc_filter,
    RefCountedPtr<ExtProcFilter::ExtProcCall> ext_proc_call,
    std::shared_ptr<ServerMetadataHandle> metadata) {
  GRPC_TRACE_LOG(ext_proc_filter, INFO)
      << "ExtProc: ServerInitialMetadataNormalMode pulled. metadata: "
      << (*metadata)->DebugString();
  Timestamp start_time = Timestamp::Now();
  // If a drain has been requested, we bypass sending the server initial
  // metadata to the external processor. Instead, we wait for the ext_proc
  // stream to close (drain complete) before propagating the metadata
  // downstream, subject to fail-open/fail-closed.
  return If(
      ext_proc_call->drain_requested(),
      [handler, ext_proc_call, metadata]() mutable {
        GRPC_TRACE_LOG(ext_proc_filter, INFO)
            << "ExtProc: Drain active before sending Server Initial Metadata, "
               "blocking propagation";
        return Map(
            ext_proc_call->WaitForStreamStatus(),
            [handler, ext_proc_call,
             metadata](absl::Status status) mutable -> absl::Status {
              GRPC_TRACE_LOG(ext_proc_filter, INFO)
                  << "ExtProc: Server Initial Metadata Drain complete "
                     "(pre-existing). Status: "
                  << status;
              if (!ext_proc_call->IsStreamClosedCleanly() &&
                  !ext_proc_call->IsFailOpenAllowed()) {
                return status;
              }
              handler.SpawnPushServerInitialMetadata(std::move(*metadata));
              return absl::OkStatus();
            });
      },
      [handler, ext_proc_filter, ext_proc_call, metadata,
       start_time]() mutable {
        return SendAndProcessServerHeadersNormalMode(
            ext_proc_call, metadata, /*end_of_stream=*/false,
            [handler, ext_proc_filter,
             start_time](ServerMetadataHandle metadata) mutable {
              ext_proc_filter->RecordServerHeadersDuration(
                  (Timestamp::Now() - start_time).seconds());
              handler.SpawnPushServerInitialMetadata(std::move(metadata));
            });
      });
}

// Sends server initial metadata to ext_proc in observability mode.
auto ServerInitialMetadataObservabilityMode(
    CallHandler handler, RefCountedPtr<ExtProcFilter> ext_proc_filter,
    RefCountedPtr<ExtProcFilter::ExtProcCall> ext_proc_call,
    std::shared_ptr<ServerMetadataHandle> metadata) {
  GRPC_TRACE_LOG(ext_proc_filter, INFO)
      << "ExtProc: ServerInitialMetadataObservabilityMode pulled. metadata: "
      << (*metadata)->DebugString();
  Timestamp start_time = Timestamp::Now();
  return Map(
      ext_proc_call->SendServerInitialMetadataRequest(
          metadata, /*end_of_stream=*/ext_proc_call->is_trailers_only()),
      [handler, ext_proc_filter, metadata,
       ext_proc_call = std::move(ext_proc_call),
       start_time](absl::Status status) mutable -> absl::Status {
        // If write failed and fail-open is not allowed, fail closed unless
        // clean stream closure occurred.
        if (!status.ok() && !ext_proc_call->IsFailOpenAllowed()) {
          if (ext_proc_call->IsStreamClosedCleanly()) {
            GRPC_TRACE_LOG(ext_proc_filter, INFO)
                << "ExtProc: Ignored server initial metadata send failure "
                   "in observability mode due to clean close: "
                << status;
          } else {
            if (ext_proc_call->IsStreamClosed() &&
                !ext_proc_call->GetStreamStatus().ok()) {
              return ext_proc_call->GetStreamStatus();
            }
            return status;
          }
        }
        // Immediately push initial metadata (or trailers-only) downstream.
        if (ext_proc_call->is_trailers_only()) {
          handler.SpawnPushServerTrailingMetadata(std::move(*metadata));
        } else {
          ext_proc_filter->RecordServerHeadersDuration(
              (Timestamp::Now() - start_time).seconds());
          handler.SpawnPushServerInitialMetadata(std::move(*metadata));
        }
        return absl::OkStatus();
      });
}

absl::AnyInvocable<Poll<absl::Status>()> ServerInitialMetadata(
    CallHandler handler, CallInitiator initiator,
    RefCountedPtr<ExtProcFilter> ext_proc_filter,
    RefCountedPtr<ExtProcFilter::ExtProcCall> ext_proc_call,
    std::shared_ptr<ServerMetadataHandle> metadata) {
  const bool send_headers =
      ext_proc_call->config()->processing_mode->send_response_headers &&
      ext_proc_call != nullptr && !ext_proc_call->IsStreamClosed() &&
      !ext_proc_call->ext_proc_stream_half_closed();
  if (!send_headers) {
    return [handler, ext_proc_call = std::move(ext_proc_call),
            metadata]() mutable {
      if (ext_proc_call != nullptr && ext_proc_call->IsStreamClosed() &&
          !ext_proc_call->IsStreamClosedCleanly() &&
          !ext_proc_call->IsFailOpenAllowed()) {
        return ext_proc_call->GetStreamStatus();
      }
      GRPC_TRACE_LOG(ext_proc_filter, INFO)
          << "ExtProc: ServerInitialMetadataNonProcessingMode metadata: "
          << (*metadata)->DebugString();
      handler.SpawnPushServerInitialMetadata(std::move(*metadata));
      return absl::OkStatus();
    };
  } else if (ext_proc_call->config()->observability_mode) {
    return ServerInitialMetadataObservabilityMode(
        handler, std::move(ext_proc_filter), std::move(ext_proc_call),
        std::move(metadata));
  } else {
    return ServerInitialMetadataNormalMode(
        handler, initiator, std::move(ext_proc_filter),
        std::move(ext_proc_call), std::move(metadata));
  }
}

// Forwards server-to-client messages in observability mode.
auto ServerToClientMessagesObservabilityMode(
    CallHandler handler, CallInitiator initiator,
    RefCountedPtr<ExtProcFilter::ExtProcCall> ext_proc_call) {
  GRPC_TRACE_LOG(ext_proc_filter, INFO)
      << "ExtProc: ServerToClientMessagesObservabilityMode started, "
      << "stream_closed=" << ext_proc_call->IsStreamClosed();
  return ForEach(MessagesFrom(initiator), [handler, ext_proc_call](
                                              MessageHandle message) mutable {
    GRPC_TRACE_LOG(ext_proc_filter, INFO)
        << "ExtProc: ServerToClientMessagesObservabilityMode "
           "processing message, stream_closed="
        << ext_proc_call->IsStreamClosed();
    return Map(If(
                   !ext_proc_call->IsStreamClosed(),
                   [ext_proc_call, &message]() {
                     // Asynchronously transmit the server response body to
                     // ext_proc for observation.
                     return ext_proc_call->SendServerMessageRequest(message);
                   },
                   []() -> absl::Status { return absl::OkStatus(); }),
               [handler, message = std::move(message),
                ext_proc_call](absl::Status status) mutable -> absl::Status {
                 // If sending to ext_proc failed and fail-open is not allowed,
                 // check if stream closed cleanly.
                 if (!status.ok() && !ext_proc_call->IsFailOpenAllowed()) {
                   if (ext_proc_call->IsStreamClosedCleanly()) {
                     GRPC_TRACE_LOG(ext_proc_filter, INFO)
                         << "ExtProc: Ignored server message send failure in "
                            "observability mode due to clean close: "
                         << status;
                   } else {
                     return status;
                   }
                 }
                 // Immediately forward the unmutated message downstream.
                 handler.SpawnPushMessage(std::move(message));
                 return absl::OkStatus();
               });
  });
}

absl::AnyInvocable<Poll<absl::Status>()>
SendServerToClientMessagesToExtProcServer(
    CallHandler handler, CallInitiator initiator,
    RefCountedPtr<ExtProcFilter::ExtProcCall> ext_proc_call) {
  GRPC_TRACE_LOG(ext_proc_filter, INFO)
      << "ExtProc: SendServerToClientMessagesToExtProcServer started";
  return Seq(
      ForEach(
          MessagesFrom(initiator),
          [handler, ext_proc_call](MessageHandle message) mutable {
            GRPC_TRACE_LOG(ext_proc_filter, INFO)
                << "ExtProc: ServerToClient S2C Write Loop pulled message, "
                   "processing";
            // We wrap MessageHandle in a std::shared_ptr because the promise
            // If(...) combinator instantiates and constructs both alternative
            // lambda branches at compile/construction time. Since MessageHandle
            // is a move-only type, it cannot be moved by value into multiple
            // lambda captures without leaving one in an invalid moved-from
            // state.
            auto shared_message =
                std::make_shared<MessageHandle>(std::move(message));
            return If(
                ext_proc_call->drain_requested(),
                // Handle drain request for server to client messages
                [ext_proc_call, handler, shared_message]() mutable {
                  GRPC_TRACE_LOG(ext_proc_filter, INFO)
                      << "ExtProc: Drain active, blocking S2C Write Loop";
                  return Map(
                      // Block forwarding data plane messages until the external
                      // processor stream has fully closed and set its final
                      // status. Once resolved, we check if we should fail open
                      // or fail closed before resuming message delivery.
                      ext_proc_call->WaitForStreamStatus(),
                      [ext_proc_call, handler, shared_message](
                          absl::Status status) mutable -> absl::Status {
                        GRPC_TRACE_LOG(ext_proc_filter, INFO)
                            << "ExtProc: S2C Drain complete, resuming S2C "
                               "bypass. Status: "
                            << status;
                        auto message = std::move(*shared_message);
                        // If stream did not close cleanly and fail-open is not
                        // allowed, return error status.
                        if (!ext_proc_call->IsStreamClosedCleanly() &&
                            !ext_proc_call->IsFailOpenAllowed()) {
                          return status;
                        }
                        // Otherwise, resume data plane bypass and push message.
                        handler.SpawnPushMessage(std::move(message));
                        return absl::OkStatus();
                      });
                },
                [handler, ext_proc_call, shared_message]() mutable {
                  const bool send_message =
                      ext_proc_call->config()
                          ->processing_mode->send_response_body &&
                      !ext_proc_call->IsStreamClosed() &&
                      !ext_proc_call->ext_proc_stream_half_closed();
                  return If(
                      send_message,
                      [handler, ext_proc_call, shared_message]() mutable {
                        return Map(
                            ext_proc_call->SendServerMessageRequest(
                                *shared_message),
                            [handler, ext_proc_call, shared_message](
                                absl::Status status) mutable -> absl::Status {
                              auto message = std::move(*shared_message);
                              if (!status.ok() ||
                                  ext_proc_call->IsStreamClosed()) {
                                // If not cleanly closed and fail-open is not
                                // allowed, return error status immediately.
                                if (!ext_proc_call->IsStreamClosedCleanly() &&
                                    !ext_proc_call->IsFailOpenAllowed()) {
                                  return ext_proc_call->IsStreamClosed()
                                             ? ext_proc_call->GetStreamStatus()
                                             : status;
                                }
                                // Otherwise, bypass ext_proc and push message
                                // directly to client.
                                handler.SpawnPushMessage(std::move(message));
                              }
                              return absl::OkStatus();
                            });
                      },
                      // When message processing is disabled or the external
                      // processor stream is closed, bypass ext_proc and forward
                      // the message directly to the client (unless stream error
                      // requires failing closed).
                      [handler, ext_proc_call, shared_message]() mutable {
                        auto message = std::move(*shared_message);
                        bool is_closed = ext_proc_call->IsStreamClosed();
                        bool is_clean = ext_proc_call->IsStreamClosedCleanly();
                        bool fail_open = ext_proc_call->IsFailOpenAllowed();
                        GRPC_TRACE_LOG(ext_proc_filter, INFO)
                            << "ExtProc: S2C bypass check: is_closed="
                            << is_closed << ", is_clean=" << is_clean
                            << ", fail_open=" << fail_open;
                        if (ext_proc_call->config()
                                ->processing_mode->send_response_body &&
                            is_closed) {
                          if (!is_clean && !fail_open) {
                            GRPC_TRACE_LOG(ext_proc_filter, INFO)
                                << "ExtProc: S2C bypass check failing closed "
                                   "with status: "
                                << ext_proc_call->GetStreamStatus();
                            return ext_proc_call->GetStreamStatus();
                          }
                        }
                        GRPC_TRACE_LOG(ext_proc_filter, INFO)
                            << "ExtProc: ServerToClient S2C Write Loop "
                               "bypassing ext_proc";
                        handler.SpawnPushMessage(std::move(message));
                        return absl::OkStatus();
                      });
                });
          }),
      // Mark server writes done when polling finishes.
      [ext_proc_call]() {
        ext_proc_call->SetServerToClientWritesDone();
        return absl::OkStatus();
      });
}

absl::AnyInvocable<Poll<absl::Status>()>
ReadServerToClientMessagesFromExtProcServer(
    CallHandler handler, CallInitiator initiator,
    RefCountedPtr<ExtProcFilter::ExtProcCall> ext_proc_call) {
  GRPC_TRACE_LOG(ext_proc_filter, INFO)
      << "ExtProc: ReadServerToClientMessagesFromExtProcServer started";
  // Read from response_body_pipe_, construct message, push to
  // handler.
  return ForEach(
      std::move(ext_proc_call->response_body_pipe().receiver),
      [handler, initiator,
       ext_proc_call](absl::StatusOr<ExtProcResponse> response) mutable {
        GRPC_TRACE_LOG(ext_proc_filter, INFO)
            << "ExtProc: ServerToClient S2C Read Loop got response";
        if (!response.ok()) {
          return response.status();
        }
        const auto& response_body =
            std::get<ExtProcResponse::ResponseBody>((*response).response);
        GRPC_TRACE_LOG(ext_proc_filter, INFO)
            << "ExtProc: ServerToClient S2C Read Loop playing body mutation: "
            << response_body.mutation.body.size() << "b";
        auto slice = Slice::FromCopiedString(response_body.mutation.body);
        auto new_msg =
            handler.arena()->MakePooled<Message>(SliceBuffer(std::move(slice)),
                                                 /*flags=*/0);
        GRPC_TRACE_LOG(ext_proc_filter, INFO)
            << "ExtProcCall " << ext_proc_call.get()
            << ": Pushing message downstream (normal mode)";
        handler.SpawnPushMessage(std::move(new_msg));
        return absl::OkStatus();
      });
}

absl::AnyInvocable<Poll<absl::Status>()> ServerToClientMessagesNormalMode(
    CallHandler handler, CallInitiator initiator,
    RefCountedPtr<ExtProcFilter::ExtProcCall> ext_proc_call) {
  GRPC_TRACE_LOG(ext_proc_filter, INFO)
      << "ExtProc: ServerToClientMessagesNormalMode started";
  return Map(TryJoin<absl::StatusOr>(
                 SendServerToClientMessagesToExtProcServer(handler, initiator,
                                                           ext_proc_call),
                 ReadServerToClientMessagesFromExtProcServer(
                     handler, initiator, std::move(ext_proc_call))),
             [](auto result) -> absl::Status { return result.status(); });
}

absl::AnyInvocable<Poll<absl::Status>()> ServerToClientMessages(
    CallHandler handler, CallInitiator initiator,
    RefCountedPtr<ExtProcFilter::ExtProcCall> ext_proc_call) {
  const bool send_body =
      ext_proc_call->config()->processing_mode->send_response_body &&
      !ext_proc_call->IsStreamClosed();
  if (!send_body) {
    GRPC_TRACE_LOG(ext_proc_filter, INFO)
        << "ExtProc: ServerToClientMessagesNonProcessingMode started";
    return ForEach(MessagesFrom(initiator),
                   [handler](MessageHandle message) mutable {
                     GRPC_TRACE_LOG(ext_proc_filter, INFO)
                         << "ExtProc: "
                            "ServerToClientMessagesNonProcessingMode "
                            "forwarding message";
                     handler.SpawnPushMessage(std::move(message));
                     return absl::OkStatus();
                   });
  } else if (ext_proc_call->config()->observability_mode) {
    return ServerToClientMessagesObservabilityMode(handler, initiator,
                                                   std::move(ext_proc_call));
  } else {
    return ServerToClientMessagesNormalMode(handler, initiator,
                                            std::move(ext_proc_call));
  }
}

absl::AnyInvocable<Poll<absl::Status>()>
ReadServerTrailingMetadataFromExtProcServer(
    CallHandler handler, CallInitiator initiator,
    RefCountedPtr<ExtProcFilter> ext_proc_filter,
    RefCountedPtr<ExtProcFilter::ExtProcCall> ext_proc_call,
    std::shared_ptr<ServerMetadataHandle> metadata, Timestamp start_time) {
  auto config = ext_proc_call->config();
  GRPC_TRACE_LOG(ext_proc_filter, INFO)
      << "ExtProc: ReadServerTrailingMetadataFromExtProcServer started";
  return Map(
      // Wait on response_trailers_latch, which is set when the external
      // processor returns the response to our ServerTrailingMetadata
      // request (or when the stream terminates/fails).
      ext_proc_call->response_trailers_latch().Wait(),
      [handler, initiator, ext_proc_filter, metadata = std::move(metadata),
       ext_proc_call = std::move(ext_proc_call), config = std::move(config),
       start_time](
          absl::StatusOr<ExtProcResponse> response) mutable -> absl::Status {
        absl::Status status = absl::OkStatus();
        if (!response.ok()) {
          status = response.status();
        } else {
          // Handle immediate response from the external processor.
          // If requested and not disabled in config, construct cancelled
          // server metadata, apply any specified header mutations, cancel the
          // call, and close the ext_proc stream.
          if (const auto* immediate =
                  std::get_if<ExtProcResponse::ImmediateResponse>(
                      &response->response);
              immediate != nullptr && (!config->disable_immediate_response ||
                                       ext_proc_call->server_trailers_sent())) {
            auto error_md = CancelledServerMetadataFromStatus(
                static_cast<grpc_status_code>(immediate->status),
                immediate->details);
            const auto* rules = config->mutation_rules.has_value()
                                    ? &config->mutation_rules.value()
                                    : nullptr;
            auto mut_status = ApplyHeaderMutations(immediate->header_mutation,
                                                   rules, *error_md);
            if (!mut_status.ok()) {
              GRPC_TRACE_LOG(ext_proc_filter, ERROR)
                  << "Failed to apply immediate response header mutations: "
                  << mut_status;
            }
            *metadata = std::move(error_md);
            GRPC_TRACE_LOG(ext_proc_filter, INFO)
                << "ExtProc: ServerTrailingMetadata pushing immediate response "
                   "metadata";
            ext_proc_filter->RecordServerTrailersDuration(
                (Timestamp::Now() - start_time).seconds());
            handler.SpawnPushServerTrailingMetadata(std::move(*metadata));
            initiator.SpawnCancel();
            ext_proc_call->CloseStream();
            return absl::OkStatus();
          }
          // When trailing metadata is received, no further body responses are
          // expected from the external processor. If body processing was
          // enabled in normal mode and the pipe sender is not yet closed,
          // explicitly close it to cleanly terminate any asynchronous body
          // read loops.
          if (!config->observability_mode) {
            if (!ext_proc_call->response_body_pipe().sender.IsClosed()) {
              ext_proc_call->response_body_pipe().sender.MarkClosed();
            }
            if (!ext_proc_call->request_body_pipe().sender.IsClosed()) {
              ext_proc_call->request_body_pipe().sender.MarkClosed();
            }
          }
          // Apply header mutations from the external processor's trailing
          // metadata response to the outgoing server trailing metadata.
          GRPC_TRACE_LOG(ext_proc_filter, INFO)
              << "ExtProc: ServerTrailingMetadata response received. "
                 "OK: true";
          if (const auto* response_trailers =
                  std::get_if<ExtProcResponse::ResponseTrailers>(
                      &response->response);
              response_trailers != nullptr) {
            const auto* rules = config->mutation_rules.has_value()
                                    ? &config->mutation_rules.value()
                                    : nullptr;
            status = ApplyHeaderMutations(response_trailers->mutation, rules,
                                          **metadata);
            GRPC_TRACE_LOG(ext_proc_filter, INFO)
                << "ExtProc: ServerTrailingMetadata mutations applied, "
                   "status: "
                << status.ToString()
                << ", mutated metadata: " << (*metadata)->DebugString();
          }
        }
        // If an error occurred while waiting for or processing the response,
        // check failure mode configuration. Unless failure_mode_allow is
        // enabled (which allows proceeding with unmutated metadata), replace
        // the trailing metadata with a cancelled status corresponding to the
        // error.
        if (!status.ok()) {
          *metadata = CancelledServerMetadataFromStatus(status);
        }
        GRPC_TRACE_LOG(ext_proc_filter, INFO)
            << "ExtProc: ServerTrailingMetadata pushing metadata immediately";
        // Push the final (mutated or error) server trailing metadata
        // downstream.
        ext_proc_filter->RecordServerTrailersDuration(
            (Timestamp::Now() - start_time).seconds());
        handler.SpawnPushServerTrailingMetadata(std::move(*metadata));
        return absl::OkStatus();
      });
}

absl::AnyInvocable<Poll<absl::Status>()> ServerTrailingMetadataNormalMode(
    CallHandler handler, CallInitiator initiator,
    RefCountedPtr<ExtProcFilter> ext_proc_filter,
    RefCountedPtr<ExtProcFilter::ExtProcCall> ext_proc_call,
    std::shared_ptr<ServerMetadataHandle> metadata) {
  GRPC_TRACE_LOG(ext_proc_filter, INFO)
      << "ExtProc: ServerTrailingMetadataNormalMode pulled. metadata: "
      << (*metadata)->DebugString();
  Timestamp start_time = Timestamp::Now();
  // If a drain has been requested, we bypass sending the server trailing
  // metadata to the external processor. Instead, we wait for the ext_proc
  // stream to close (drain complete) before propagating the metadata
  // downstream, subject to fail-open/fail-closed policies.
  return If(
      ext_proc_call->drain_requested(),
      [handler, ext_proc_call, metadata]() mutable {
        GRPC_TRACE_LOG(ext_proc_filter, INFO)
            << "ExtProc: Drain active before sending Server Trailing Metadata, "
               "blocking propagation";
        return Map(
            ext_proc_call->WaitForStreamStatus(),
            [handler, ext_proc_call = std::move(ext_proc_call),
             metadata = std::move(metadata)](
                absl::Status status) mutable -> absl::Status {
              GRPC_TRACE_LOG(ext_proc_filter, INFO)
                  << "ExtProc: Server Trailing Metadata Drain complete "
                     "(pre-existing). Status: "
                  << status;
              if (!ext_proc_call->IsStreamClosedCleanly() &&
                  !ext_proc_call->IsFailOpenAllowed()) {
                return status;
              }
              handler.SpawnPushServerTrailingMetadata(std::move(*metadata));
              return absl::OkStatus();
            });
      },
      [handler, initiator, ext_proc_filter, ext_proc_call, metadata,
       start_time]() mutable {
        return Seq(
            ext_proc_call->SendServerTrailingMetadataRequest(metadata),
            [handler, initiator, ext_proc_filter,
             ext_proc_call = ext_proc_call->Ref(), metadata,
             start_time](absl::Status status) mutable
                -> absl::AnyInvocable<Poll<absl::Status>()> {
              if (!status.ok()) {
                if (ext_proc_call->IsFailOpenAllowed()) {
                  GRPC_TRACE_LOG(ext_proc_filter, INFO)
                      << "ExtProc: Server trailing metadata send failed, but "
                         "fail-open is allowed. Error: "
                      << status;
                  handler.SpawnPushServerTrailingMetadata(std::move(*metadata));
                  return
                      []() -> Poll<absl::Status> { return absl::OkStatus(); };
                }
                absl::Status err = ext_proc_call->IsStreamClosed()
                                       ? ext_proc_call->GetStreamStatus()
                                       : status;
                return [err]() -> Poll<absl::Status> { return err; };
              }
              return ReadServerTrailingMetadataFromExtProcServer(
                  handler, initiator, ext_proc_filter, std::move(ext_proc_call),
                  std::move(metadata), start_time);
            });
      });
}

absl::AnyInvocable<Poll<absl::Status>()>
ServerTrailingMetadataObservabilityMode(
    CallHandler handler, RefCountedPtr<ExtProcFilter> ext_proc_filter,
    RefCountedPtr<ExtProcFilter::ExtProcCall> ext_proc_call,
    std::shared_ptr<ServerMetadataHandle> metadata) {
  GRPC_TRACE_LOG(ext_proc_filter, INFO)
      << "ExtProc: ServerTrailingMetadataObservabilityMode pulled. metadata: "
      << (*metadata)->DebugString();
  Timestamp start_time = Timestamp::Now();
  // Asynchronously send the ServerTrailers message to the external processor
  // provided the ext_proc stream is still open. In observability mode, traffic
  // is strictly observed and not modified.
  return Seq(
      ext_proc_call->SendServerTrailingMetadataRequest(metadata),
      [handler, ext_proc_filter, metadata,
       ext_proc_call = std::move(ext_proc_call),
       start_time](absl::Status status) mutable {
        // Ensure the response body pipe sender is marked closed when trailing
        // metadata arrives, cleanly terminating any ongoing asynchronous read
        // loops.
        if (ext_proc_call->config()->processing_mode->send_response_body &&
            !ext_proc_call->config()->observability_mode &&
            !ext_proc_call->response_body_pipe().sender.IsClosed()) {
          ext_proc_call->response_body_pipe().sender.MarkClosed();
        }
        // If sending the message failed or the ext_proc stream closed with an
        // error (e.g., disconnection or RESOURCE_EXHAUSTED), check failure mode
        // configuration. Unless failure_mode_allow is enabled (which allows
        // proceeding despite observability failures), replace the trailing
        // metadata with a cancelled status corresponding to the error.
        if ((!status.ok() || ext_proc_call->IsStreamClosed()) &&
            !ext_proc_call->IsFailOpenAllowed()) {
          if (ext_proc_call->IsStreamClosedCleanly()) {
            GRPC_TRACE_LOG(ext_proc_filter, INFO)
                << "ExtProc: Ignored server trailing metadata send failure "
                   "in observability mode due to clean close: "
                << status;
          } else {
            absl::Status error_status = status;
            if (ext_proc_call->IsStreamClosed() &&
                !ext_proc_call->GetStreamStatus().ok()) {
              error_status = ext_proc_call->GetStreamStatus();
            }
            if (!error_status.ok()) {
              *metadata = CancelledServerMetadataFromStatus(error_status);
            }
          }
        }
        GRPC_TRACE_LOG(ext_proc_filter, INFO)
            << "ExtProc: ServerTrailingMetadata pushing metadata immediately";
        // Immediately push the server trailing metadata downstream without
        // waiting for an ext_proc response.
        ext_proc_filter->RecordServerTrailersDuration(
            (Timestamp::Now() - start_time).seconds());
        handler.SpawnPushServerTrailingMetadata(std::move(*metadata));
        return absl::OkStatus();
      });
}

absl::AnyInvocable<Poll<absl::Status>()>
ServerTrailingMetadataNonProcessingMode(
    CallHandler handler,
    RefCountedPtr<ExtProcFilter::ExtProcCall> ext_proc_call,
    std::shared_ptr<ServerMetadataHandle> metadata) {
  GRPC_TRACE_LOG(ext_proc_filter, INFO)
      << "ExtProc: ServerTrailingMetadataNonProcessingMode pulled. metadata: "
      << (*metadata)->DebugString();
  // Even when trailing metadata is not sent to ext_proc, its arrival signals
  // that no further response bodies will be sent. If body processing was
  // enabled, explicitly close the pipe sender to cleanly terminate any
  // asynchronous body read loops.
  if (ext_proc_call->config()->processing_mode->send_response_body &&
      !ext_proc_call->config()->observability_mode &&
      !ext_proc_call->response_body_pipe().sender.IsClosed()) {
    ext_proc_call->response_body_pipe().sender.MarkClosed();
  }
  GRPC_TRACE_LOG(ext_proc_filter, INFO)
      << "ExtProc: ServerTrailingMetadata pushing metadata immediately";
  // Immediately push the unmutated server trailing metadata downstream.
  handler.SpawnPushServerTrailingMetadata(std::move(*metadata));
  return []() -> Poll<absl::Status> { return absl::OkStatus(); };
}

// Handles server trailing metadata in normal mode for "trailers-only"
// responses (when an RPC terminates immediately without sending initial
// metadata or response body).
// Since it is trailers-only, it sends a ServerHeaders request to the external
// processor (with end_of_stream=true), waits for the response, applies
// mutations or handles immediate responses, and pushes the final metadata
// downstream.
absl::AnyInvocable<Poll<absl::Status>()>
ServerTrailingMetadataTrailersOnlyNormalMode(
    CallHandler handler, CallInitiator initiator,
    RefCountedPtr<ExtProcFilter> ext_proc_filter,
    RefCountedPtr<ExtProcFilter::ExtProcCall> ext_proc_call,
    std::shared_ptr<ServerMetadataHandle> metadata) {
  GRPC_TRACE_LOG(ext_proc_filter, INFO)
      << "ExtProc: ServerTrailingMetadataTrailersOnlyNormalMode started";
  Timestamp start_time = Timestamp::Now();
  // If a drain has been requested, we bypass sending the server trailing
  // metadata to the external processor. Instead, we wait for the ext_proc
  // stream to close (drain complete) before propagating the metadata
  // downstream, subject to fail-open/fail-closed policies (trailers-only case).
  return If(
      ext_proc_call->drain_requested(),
      [ext_proc_call, handler, metadata]() mutable {
        GRPC_TRACE_LOG(ext_proc_filter, INFO)
            << "ExtProc: Drain active before sending Server Trailing Metadata "
               "(Trailers Only), blocking propagation";
        return Map(
            ext_proc_call->WaitForStreamStatus(),
            [ext_proc_call, handler,
             metadata](absl::Status status) mutable -> absl::Status {
              GRPC_TRACE_LOG(ext_proc_filter, INFO)
                  << "ExtProc: Server Trailing Metadata (Trailers Only) Drain "
                     "complete (pre-existing). Status: "
                  << status;
              if (!ext_proc_call->IsStreamClosedCleanly() &&
                  !ext_proc_call->IsFailOpenAllowed()) {
                return status;
              }
              handler.SpawnPushServerTrailingMetadata(std::move(*metadata));
              return absl::OkStatus();
            });
      },
      [handler, initiator, ext_proc_filter, ext_proc_call, metadata,
       start_time]() mutable {
        // Send the trailers-only metadata as ServerHeaders (with
        // end_of_stream=true).
        return SendAndProcessServerHeadersNormalMode(
            ext_proc_call, metadata, /*end_of_stream=*/true,
            [handler, ext_proc_filter,
             start_time](ServerMetadataHandle metadata) mutable {
              ext_proc_filter->RecordServerHeadersDuration(
                  (Timestamp::Now() - start_time).seconds());
              handler.SpawnPushServerTrailingMetadata(std::move(metadata));
            });
      });
}

// Helper that checks if the external processor stream is already closed or
// half-closed.
// If it closed with an error and the configuration does NOT allow fail-open
// (server_fail_open_allowed=false), returns a promise resolving to that error.
// If it closed cleanly, or closed with error but fail-open IS allowed,
// falls back to pushing the unmutated trailing metadata downstream immediately.
// Returns std::nullopt if the stream is active and processing should continue.
absl::optional<absl::AnyInvocable<Poll<absl::Status>()>>
MaybeHandleClosedStream(CallHandler handler,
                        RefCountedPtr<ExtProcFilter::ExtProcCall> ext_proc_call,
                        std::shared_ptr<ServerMetadataHandle> metadata) {
  if (ext_proc_call->IsStreamClosed() ||
      ext_proc_call->ext_proc_stream_half_closed()) {
    absl::Status error = ext_proc_call->GetStreamStatus();
    if (!error.ok() && !ext_proc_call->IsFailOpenAllowed()) {
      return [error]() -> Poll<absl::Status> { return error; };
    }
    return ServerTrailingMetadataNonProcessingMode(
        handler, std::move(ext_proc_call), std::move(metadata));
  }
  return std::nullopt;
}

// Orchestrates the server trailing metadata step when the RPC is
// "trailers-only". (i.e. backend immediately sent trailing metadata without any
// preceding body or initial metadata).
absl::AnyInvocable<Poll<absl::Status>()> ServerTrailingMetadataTrailersOnly(
    CallHandler handler, CallInitiator initiator,
    RefCountedPtr<ExtProcFilter> ext_proc_filter,
    RefCountedPtr<ExtProcFilter::ExtProcCall> ext_proc_call,
    std::shared_ptr<ServerMetadataHandle> metadata) {
  // If the ext_proc stream has closed prematurely, route immediately to
  // error propagation or unmutated fallback.
  if (auto promise = MaybeHandleClosedStream(handler, ext_proc_call, metadata);
      promise.has_value()) {
    return std::move(*promise);
  }
  // Determine if we should attempt to send trailers-only headers to the
  // processor, which requires the config setting and an active ext_proc stream.
  const bool send_headers =
      ext_proc_call->config()->processing_mode->send_response_headers &&
      !ext_proc_call->IsStreamClosed() &&
      !ext_proc_call->ext_proc_stream_half_closed();
  // Route to the appropriate handler based on configuration.
  if (!send_headers) {
    return ServerTrailingMetadataNonProcessingMode(
        handler, std::move(ext_proc_call), std::move(metadata));
  } else if (ext_proc_call->config()->observability_mode) {
    return ServerInitialMetadataObservabilityMode(
        handler, std::move(ext_proc_filter), std::move(ext_proc_call),
        std::move(metadata));
  } else {
    return ServerTrailingMetadataTrailersOnlyNormalMode(
        handler, initiator, std::move(ext_proc_filter),
        std::move(ext_proc_call), std::move(metadata));
  }
}

// Orchestrates the server trailing metadata step for a normal RPC (one that has
// sent initial metadata and/or response body before finishing).
absl::AnyInvocable<Poll<absl::Status>()> ServerTrailingMetadataNormal(
    CallHandler handler, CallInitiator initiator,
    RefCountedPtr<ExtProcFilter> ext_proc_filter,
    RefCountedPtr<ExtProcFilter::ExtProcCall> ext_proc_call,
    std::shared_ptr<ServerMetadataHandle> metadata) {
  // If the ext_proc stream has closed prematurely, route immediately to
  // error propagation or unmutated fallback.
  if (auto promise = MaybeHandleClosedStream(handler, ext_proc_call, metadata);
      promise.has_value()) {
    return std::move(*promise);
  }
  // Determine if we should attempt to send trailers to the processor.
  // Trailers are only sent if processing is enabled in config, the backend
  // returned an OK status (errors skip trailing metadata processing), and the
  // ext_proc stream is active.
  const bool send_trailers =
      ext_proc_call->config()->processing_mode->send_response_trailers &&
      IsStatusOk(*metadata) && !ext_proc_call->IsStreamClosed() &&
      !ext_proc_call->ext_proc_stream_half_closed();
  if (!send_trailers) {
    return ServerTrailingMetadataNonProcessingMode(
        handler, std::move(ext_proc_call), std::move(metadata));
  } else if (ext_proc_call->config()->observability_mode) {
    return ServerTrailingMetadataObservabilityMode(
        handler, std::move(ext_proc_filter), std::move(ext_proc_call),
        std::move(metadata));
  } else {
    return ServerTrailingMetadataNormalMode(
        handler, initiator, std::move(ext_proc_filter),
        std::move(ext_proc_call), std::move(metadata));
  }
}

// Main dispatcher function for the ServerTrailingMetadata filter interceptor
// step. Distinguishes between "trailers-only" RPCs and normal RPCs and routes
// accordingly.
absl::AnyInvocable<Poll<absl::Status>()> ServerTrailingMetadata(
    CallHandler handler, CallInitiator initiator,
    RefCountedPtr<ExtProcFilter> ext_proc_filter,
    RefCountedPtr<ExtProcFilter::ExtProcCall> ext_proc_call,
    std::shared_ptr<ServerMetadataHandle> metadata) {
  // Check if this response is "trailers-only" (i.e. backend ended the RPC
  // immediately without sending response headers first).
  const bool is_trailers_only =
      (*metadata)->get(GrpcTrailersOnly()).value_or(false);
  if (is_trailers_only) {
    ext_proc_call->SetIsTrailersOnly();
  }
  // Dispatch to the appropriate handler based on whether the response is
  // trailers-only.
  if (is_trailers_only) {
    return ServerTrailingMetadataTrailersOnly(
        handler, initiator, std::move(ext_proc_filter),
        std::move(ext_proc_call), std::move(metadata));
  }
  return ServerTrailingMetadataNormal(
      handler, initiator, std::move(ext_proc_filter), std::move(ext_proc_call),
      std::move(metadata));
}

// Intercepts and processes client-to-server messages.
// Forwards client messages to backend without processing when request body
// processing is disabled or ext_proc stream is closed.
absl::AnyInvocable<Poll<absl::Status>()>
ClientToServerMessagesNonProcessingMode(
    CallHandler handler, CallInitiator initiator,
    RefCountedPtr<ExtProcFilter::ExtProcCall> ext_proc_call) {
  GRPC_TRACE_LOG(ext_proc_filter, INFO)
      << "ExtProc: ClientToServerMessagesNonProcessingMode started";
  return Seq(
      ForEach(MessagesFrom(handler),
              [initiator, ext_proc_call](MessageHandle message) mutable {
                GRPC_TRACE_LOG(ext_proc_filter, INFO)
                    << "ExtProc: ClientToServerMessagesNonProcessingMode got "
                       "message";
                return If(
                    ext_proc_call->ext_proc_set_eos(),
                    []() -> absl::Status {
                      return absl::InternalError(
                          "Client sends closed by external processor");
                    },
                    [initiator, message = std::move(message)]() mutable {
                      initiator.SpawnPushMessage(std::move(message));
                      return absl::OkStatus();
                    });
              }),
      [handler, initiator]() mutable {
        GRPC_TRACE_LOG(ext_proc_filter, INFO)
            << "ExtProc: ClientToServerMessagesNonProcessingMode finished "
               "sends";
        initiator.SpawnFinishSends();
        return absl::OkStatus();
      });
}

// Handles client-to-server messages in observability mode
absl::AnyInvocable<Poll<absl::Status>()>
ClientToServerMessagesObservabilityMode(
    CallHandler handler, CallInitiator initiator,
    RefCountedPtr<ExtProcFilter> ext_proc_filter,
    RefCountedPtr<ExtProcFilter::ExtProcCall> ext_proc_call,
    ::google_protobuf_Struct* attributes) {
  GRPC_TRACE_LOG(ext_proc_filter, INFO)
      << "ExtProc: ClientToServerMessagesObservabilityMode started";
  return TrySeq(
      ForEach(
          MessagesFrom(handler),
          [initiator, ext_proc_call,
           attributes](MessageHandle message) mutable {
            GRPC_TRACE_LOG(ext_proc_filter, INFO)
                << "ExtProc: ClientToServerMessagesObservabilityMode "
                   "got message: "
                << (message != nullptr ? message->payload()->JoinIntoString()
                                       : "null");
            // If the external processor has already signaled end-of-stream
            // (EOS) for the client-to-server direction, we must fail the call
            // because the client is attempting to send more data.
            return If(
                ext_proc_call->ext_proc_set_eos(),
                []() -> absl::Status {
                  return absl::InternalError(
                      "Client sends closed by external processor");
                },
                [initiator, ext_proc_call, attributes,
                 message = std::move(message)]() mutable {
                  return Map(
                      If(
                          !ext_proc_call->IsStreamClosed(),
                          [ext_proc_call, &message, attributes]() {
                            return ext_proc_call->SendClientMessageRequest(
                                message,
                                /*end_of_stream=*/false,
                                /*end_of_stream_without_message=*/false,
                                attributes);
                          },
                          []() -> absl::Status { return absl::OkStatus(); }),
                      [initiator, message = std::move(message), ext_proc_call](
                          absl::Status status) mutable -> absl::Status {
                        GRPC_TRACE_LOG(ext_proc_filter, INFO)
                            << "ExtProc: "
                               "ClientToServerMessagesObservabilityMode "
                               "send completed: "
                            << status;
                        // If the send failed and fail-closed is configured, we
                        // fail the call. However, if the stream was closed
                        // cleanly by the server (e.g. trailers received), we
                        // ignore the failure to allow the call to complete.
                        if (!status.ok() &&
                            !ext_proc_call->config()->failure_mode_allow) {
                          if (ext_proc_call->IsStreamClosedCleanly()) {
                            GRPC_TRACE_LOG(ext_proc_filter, INFO)
                                << "ExtProc: Ignored client message send "
                                   "failure in observability mode due to "
                                   "clean close: "
                                << status;
                          } else {
                            return status;
                          }
                        }
                        // Forward the message to the backend.
                        initiator.SpawnPushMessage(std::move(message));
                        return absl::OkStatus();
                      });
                });
          }),
      // After client finishes sending all messages (WritesDone).
      [handler, initiator, ext_proc_filter, ext_proc_call,
       attributes]() mutable {
        GRPC_TRACE_LOG(ext_proc_filter, INFO)
            << "ExtProc: ClientToServerMessagesObservabilityMode finished "
               "sends";
        Timestamp start_time = Timestamp::Now();
        return Map(If(
                       !ext_proc_call->IsStreamClosed(),
                       [ext_proc_call, attributes]() {
                         MessageHandle null_msg = nullptr;
                         return ext_proc_call->SendClientMessageRequest(
                             null_msg,
                             /*end_of_stream=*/false,
                             /*end_of_stream_without_message=*/true,
                             attributes);
                       },
                       []() -> absl::Status { return absl::OkStatus(); }),
                   [handler, initiator, ext_proc_filter,
                    start_time](absl::Status status) mutable -> absl::Status {
                     if (!status.ok()) {
                       GRPC_TRACE_LOG(ext_proc_filter, INFO)
                           << "ExtProc: Failed to send client half-close in "
                              "observability mode: "
                           << status;
                     }
                     ext_proc_filter->RecordClientHalfCloseDuration(
                         (Timestamp::Now() - start_time).seconds());
                     initiator.SpawnFinishSends();
                     return absl::OkStatus();
                   });
      });
}

absl::AnyInvocable<Poll<absl::Status>()> ClientToSidestreamNormalMode(
    CallHandler handler, CallInitiator initiator,
    RefCountedPtr<ExtProcFilter> ext_proc_filter,
    RefCountedPtr<ExtProcFilter::ExtProcCall> ext_proc_call,
    ::google_protobuf_Struct* attributes) {
  return TrySeq(
      ForEach(
          MessagesFrom(handler),
          [initiator, ext_proc_call,
           attributes](MessageHandle message) mutable {
            // We wrap MessageHandle in a std::shared_ptr because the promise
            // If(...) combinator instantiates and constructs both alternative
            // lambda branches at compile/construction time. Since MessageHandle
            // is a move-only type, it cannot be moved by value into multiple
            // lambda captures without leaving one in an invalid moved-from
            // state.
            auto shared_message =
                std::make_shared<MessageHandle>(std::move(message));
            return If(
                ext_proc_call->drain_requested(),
                [ext_proc_call, initiator, shared_message]() mutable {
                  GRPC_TRACE_LOG(ext_proc_filter, INFO)
                      << "ExtProc: Drain active, blocking data plane read";
                  return Map(ext_proc_call->WaitForStreamStatus(),
                             [ext_proc_call, initiator, shared_message](
                                 absl::Status status) mutable -> absl::Status {
                               GRPC_TRACE_LOG(ext_proc_filter, INFO)
                                   << "ExtProc: Drain complete (stream "
                                      "closed), resuming data plane. Status: "
                                   << status;
                               // If stream did not close cleanly and fail-open
                               // is not allowed, return error status.
                               if (!ext_proc_call->IsStreamClosedCleanly() &&
                                   !ext_proc_call->IsFailOpenAllowed()) {
                                 return ext_proc_call->GetStreamStatus();
                               }
                               // Otherwise, resume data plane bypass and
                               // push message.
                               if (*shared_message != nullptr) {
                                 initiator.SpawnPushMessage(
                                     std::move(*shared_message));
                               }
                               return absl::OkStatus();
                             });
                },
                [initiator, ext_proc_call, attributes,
                 shared_message]() mutable {
                  return If(
                      ext_proc_call->ext_proc_set_eos(),
                      []() {
                        // TODO(rishesh): Once PH2 work is done, we should make
                        // this pass (discard or handle cleanly). Currently we
                        // fail the RPC to avoid crashes on half-closed
                        // transport.
                        return absl::InternalError(
                            "Client sends closed by external processor");
                      },
                      [initiator, ext_proc_call, attributes,
                       shared_message]() mutable {
                        const bool send_message =
                            !ext_proc_call->IsStreamClosed() &&
                            !ext_proc_call->ext_proc_stream_half_closed();
                        return Map(
                            If(
                                send_message,
                                [ext_proc_call, shared_message, attributes]() {
                                  return ext_proc_call
                                      ->SendClientMessageRequest(
                                          *shared_message,
                                          /*end_of_stream=*/false,
                                          /*end_of_stream_without_message=*/
                                          false, attributes);
                                },
                                []() -> absl::Status {
                                  return absl::OkStatus();
                                }),
                            [ext_proc_call, initiator, send_message,
                             shared_message](
                                absl::Status status) mutable -> absl::Status {
                              if (!send_message) {
                                // Stream closed before we could send. If not
                                // cleanly closed and fail-open is not allowed,
                                // return error status immediately.
                                if (!ext_proc_call->IsStreamClosedCleanly() &&
                                    !ext_proc_call->IsFailOpenAllowed()) {
                                  return ext_proc_call->IsStreamClosed()
                                             ? ext_proc_call->GetStreamStatus()
                                             : status;
                                }
                                // Otherwise, bypass ext_proc and push message.
                                if (*shared_message != nullptr) {
                                  initiator.SpawnPushMessage(
                                      std::move(*shared_message));
                                }
                                return absl::OkStatus();
                              }
                              // Message was sent, wait for response in
                              // sidestream_to_server loop.
                              if (!status.ok() ||
                                  ext_proc_call->IsStreamClosed()) {
                                // If not cleanly closed and fail-open is not
                                // allowed, return error status immediately.
                                if (!ext_proc_call->IsStreamClosedCleanly() &&
                                    !ext_proc_call->IsFailOpenAllowed()) {
                                  return ext_proc_call->IsStreamClosed()
                                             ? ext_proc_call->GetStreamStatus()
                                             : status;
                                }
                                // Otherwise, bypass ext_proc and push message.
                                if (*shared_message != nullptr) {
                                  initiator.SpawnPushMessage(
                                      std::move(*shared_message));
                                }
                              }
                              return absl::OkStatus();
                            });
                      });
                });
          }),
      [initiator, ext_proc_call, attributes]() mutable {
        // This promise runs when the client has finished sending all messages
        // (WritesDone). We must transition the client-to-server direction to
        // half-closed.
        return If(
            ext_proc_call->ext_proc_set_eos(),
            // If the external processor already closed the stream (EOS),
            // we don't need to notify it. Just mark client sends as done.
            [ext_proc_call]() {
              ext_proc_call->SetClientSendsDone();
              return absl::OkStatus();
            },
            [initiator, ext_proc_call, attributes]() mutable {
              // Prepare an empty message with
              // end_of_stream_without_message=true to signal half-close to the
              // external processor.
              MessageHandle null_msg = nullptr;
              const bool send_message =
                  !ext_proc_call->IsStreamClosed() &&
                  !ext_proc_call->ext_proc_stream_half_closed();
              return Map(
                  If(
                      send_message,
                      [ext_proc_call, attributes]() {
                        MessageHandle null_msg = nullptr;
                        return ext_proc_call->SendClientMessageRequest(
                            null_msg,
                            /*end_of_stream=*/false,
                            /*end_of_stream_without_message=*/true, attributes);
                      },
                      []() -> absl::Status { return absl::OkStatus(); }),
                  [ext_proc_call, initiator,
                   send_message](absl::Status status) mutable -> absl::Status {
                    // If we did not attempt to send the half-close (because the
                    // stream was already closed), or if the send failed/stream
                    // closed during send: we must decide whether to fail the
                    // call or bypass the error.
                    if (!send_message) {
                      if (ext_proc_call->drain_requested() ||
                          ext_proc_call->IsStreamClosedCleanly() ||
                          ext_proc_call->IsFailOpenAllowed()) {
                        // Bypass error: signal half-close to backend
                        // immediately since we won't get a response from
                        // ext_proc.
                        initiator.SpawnFinishSends();
                        ext_proc_call->SetClientSendsDone();
                        return absl::OkStatus();
                      } else {
                        // Fail-closed: propagate the stream error.
                        return ext_proc_call->IsStreamClosed()
                                   ? ext_proc_call->GetStreamStatus()
                                   : status;
                      }
                    }
                    if (!status.ok() || ext_proc_call->IsStreamClosed()) {
                      if (ext_proc_call->IsStreamClosedCleanly() ||
                          ext_proc_call->IsFailOpenAllowed()) {
                        // Bypass error: signal half-close to backend
                        // immediately.
                        initiator.SpawnFinishSends();
                        ext_proc_call->SetClientSendsDone();
                        return absl::OkStatus();
                      } else {
                        // Fail-closed: propagate the stream error.
                        return ext_proc_call->IsStreamClosed()
                                   ? ext_proc_call->GetStreamStatus()
                                   : status;
                      }
                    }
                    // Success: The half-close request was sent to ext_proc.
                    // We do NOT call initiator.SpawnFinishSends() here because
                    // we must wait for the ext_proc server to respond and close
                    // the receiver pipe. The `sidestream_to_server` promise
                    // will handle calling SpawnFinishSends() when that happens.
                    ext_proc_call->SetClientSendsDone();
                    return absl::OkStatus();
                  });
            });
      });
}

// Handles processing responses from the external processing server (sidestream)
// and forwarding the (possibly mutated) request body to the backend server.
absl::AnyInvocable<Poll<absl::Status>()> SidestreamToServerNormalMode(
    CallHandler handler, CallInitiator initiator,
    RefCountedPtr<ExtProcFilter> ext_proc_filter,
    RefCountedPtr<ExtProcFilter::ExtProcCall> ext_proc_call) {
  return Seq(
      ForEach(std::move(ext_proc_call->request_body_pipe().receiver),
              [handler, initiator,
               ext_proc_call](absl::StatusOr<ExtProcResponse> result) mutable {
                GRPC_TRACE_LOG(ext_proc_filter, INFO)
                    << "ExtProc: sidestream_to_server ForEach got item, ok: "
                    << result.ok();
                if (!result.ok()) {
                  // If the stream failed but fail-open is allowed, we ignore
                  // the error and proceed. Otherwise, we propagate the error.
                  if (ext_proc_call->IsFailOpenAllowed()) {
                    return absl::OkStatus();
                  }
                  return result.status();
                }
                // Handle request body mutation.
                if (const auto* request_body =
                        std::get_if<ExtProcResponse::RequestBody>(
                            &result->response)) {
                  // Forward the mutated body to the backend server.
                  if (!request_body->mutation.end_of_stream_without_message) {
                    GRPC_TRACE_LOG(ext_proc_filter, INFO)
                        << "ExtProc: ClientToServerMessages playing body "
                           "mutation: "
                        << request_body->mutation.body.size() << "b";
                    auto slice =
                        Slice::FromCopiedString(request_body->mutation.body);
                    auto new_msg = initiator.arena()->MakePooled<Message>(
                        SliceBuffer(std::move(slice)),
                        /*flags=*/0);
                    initiator.SpawnPushMessage(std::move(new_msg));
                  }
                }
                return absl::OkStatus();
              }),
      // This lambda runs after the ForEach loop finishes (either due to EOF or
      // error).
      [handler, initiator, ext_proc_filter,
       ext_proc_call](absl::Status status) mutable {
        Timestamp start_time = Timestamp::Now();
        GRPC_TRACE_LOG(ext_proc_filter, INFO)
            << "ExtProc: ClientToServerMessages finished sends, status: "
            << status.ToString()
            << ", c2s_write_done: " << ext_proc_call->c2s_write_done()
            << ", IsStreamClosed: " << ext_proc_call->IsStreamClosed();
        // If we have finished sending all client messages to the ext_proc
        // server, or if the ext_proc stream was closed (e.g. due to immediate
        // response), we signal the backend server that we are done sending the
        // request body.
        if (ext_proc_call->c2s_write_done() ||
            !ext_proc_call->IsStreamClosed()) {
          GRPC_TRACE_LOG(ext_proc_filter, INFO)
              << "ExtProc: Calling SpawnFinishSends";
          ext_proc_filter->RecordClientHalfCloseDuration(
              (Timestamp::Now() - start_time).seconds());
          initiator.SpawnFinishSends();
        }
        return status;
      });
}

absl::AnyInvocable<Poll<absl::Status>()> ClientToServerMessagesNormalMode(
    CallHandler handler, CallInitiator initiator,
    RefCountedPtr<ExtProcFilter> ext_proc_filter,
    RefCountedPtr<ExtProcFilter::ExtProcCall> ext_proc_call,
    ::google_protobuf_Struct* attributes) {
  return Map(
      TryJoin<absl::StatusOr>(
          ClientToSidestreamNormalMode(handler, initiator, ext_proc_filter,
                                       ext_proc_call, attributes),
          SidestreamToServerNormalMode(handler, initiator, ext_proc_filter,
                                       ext_proc_call)),
      [ext_proc_call = std::move(ext_proc_call)](auto result) -> absl::Status {
        GRPC_TRACE_LOG(ext_proc_filter, INFO)
            << "ClientToServerMessagesNormalMode result: " << result.status()
            << ", fail_open_allowed: " << ext_proc_call->IsFailOpenAllowed()
            << ", stream_error: " << ext_proc_call->GetStreamStatus();
        if (!result.ok()) {
          return result.status();
        }
        if (ext_proc_call->IsFailOpenAllowed()) {
          return absl::OkStatus();
        }
        return ext_proc_call->GetStreamStatus();
      });
}

absl::AnyInvocable<Poll<absl::Status>()> ClientToServerMessages(
    CallHandler handler, CallInitiator initiator,
    RefCountedPtr<ExtProcFilter> ext_proc_filter,
    RefCountedPtr<ExtProcFilter::ExtProcCall> ext_proc_call,
    ::google_protobuf_Struct* attributes) {
  const bool send_request_body =
      ext_proc_call->config()->processing_mode->send_request_body &&
      !ext_proc_call->IsStreamClosed();
  if (!send_request_body) {
    return ClientToServerMessagesNonProcessingMode(handler, initiator,
                                                   std::move(ext_proc_call));
  } else if (ext_proc_call->config()->observability_mode) {
    return ClientToServerMessagesObservabilityMode(
        handler, initiator, std::move(ext_proc_filter),
        std::move(ext_proc_call), attributes);
  } else {
    return ClientToServerMessagesNormalMode(
        handler, initiator, std::move(ext_proc_filter),
        std::move(ext_proc_call), attributes);
  }
}

}  // namespace

//
// ExtProcFilter
//

const grpc_channel_filter ExtProcFilter::kFilterVtable = MakePromiseBasedFilter<
    ExtProcFilter, FilterEndpoint::kClient,
    kFilterExaminesServerInitialMetadata | kFilterExaminesOutboundMessages |
        kFilterExaminesInboundMessages | kFilterExaminesCallContext>();

absl::StatusOr<RefCountedPtr<ExtProcFilter>> ExtProcFilter::Create(
    const ChannelArgs& args, ChannelFilter::Args filter_args) {
  if (filter_args.config() == nullptr) {
    return absl::InvalidArgumentError("ext_proc filter config is missing");
  }
  if (filter_args.config()->type() != Config::Type()) {
    return absl::InternalError("ext_proc filter config has wrong type");
  }
  auto config = filter_args.config().TakeAsSubclass<const Config>();
  return MakeRefCounted<ExtProcFilter>(args, std::move(config));
}

ExtProcFilter::ExtProcFilter(const ChannelArgs& args,
                             RefCountedPtr<const Config> config)
    : config_(std::move(config)),
      event_engine_(
          args.GetObjectRef<grpc_event_engine::experimental::EventEngine>()),
      default_authority_(Slice::FromCopiedString(
          args.GetString(GRPC_ARG_DEFAULT_AUTHORITY)
              .value_or(
                  CoreConfiguration::Get()
                      .resolver_registry()
                      .GetDefaultAuthority(
                          args.GetString(GRPC_ARG_SERVER_URI).value_or(""))))),
      target_(args.GetString(GRPC_ARG_SERVER_URI).value_or("")),
      is_client_(true),
      stats_plugin_group_(
          args.GetObjectRef<GlobalStatsPluginRegistry::StatsPluginGroup>()) {}

void ExtProcFilter::RecordClientHeadersDuration(double duration_seconds) const {
  if (stats_plugin_group_ != nullptr && is_client_) {
    stats_plugin_group_->RecordHistogram(
        kMetricClientExtProcClientHeadersDuration, duration_seconds, {target_},
        {});
  }
}

void ExtProcFilter::RecordClientHalfCloseDuration(
    double duration_seconds) const {
  if (stats_plugin_group_ != nullptr && is_client_) {
    stats_plugin_group_->RecordHistogram(
        kMetricClientExtProcClientHalfCloseDuration, duration_seconds,
        {target_}, {});
  }
}

void ExtProcFilter::RecordServerHeadersDuration(double duration_seconds) const {
  if (stats_plugin_group_ != nullptr && is_client_) {
    stats_plugin_group_->RecordHistogram(
        kMetricClientExtProcServerHeadersDuration, duration_seconds, {target_},
        {});
  }
}

void ExtProcFilter::RecordServerTrailersDuration(
    double duration_seconds) const {
  if (stats_plugin_group_ != nullptr && is_client_) {
    stats_plugin_group_->RecordHistogram(
        kMetricClientExtProcServerTrailersDuration, duration_seconds, {target_},
        {});
  }
}

absl::AnyInvocable<Poll<absl::Status>()>
ExtProcFilter::ClientToServerObservabilityMode(
    CallHandler handler, RefCountedPtr<ExtProcCall> ext_proc_call) {
  Timestamp start_time = Timestamp::Now();
  return TrySeq(
      handler.PullClientInitialMetadata(),
      [handler, ext_proc_filter = RefAsSubclass<ExtProcFilter>(),
       ext_proc_call = std::move(ext_proc_call),
       start_time](ClientMetadataHandle metadata) mutable
          -> absl::AnyInvocable<Poll<absl::Status>()> {
        GRPC_TRACE_LOG(ext_proc_filter, INFO)
            << "ExtProc: Client initial metadata received "
               "(observability):\n"
            << metadata->DebugString();
        auto shared_metadata =
            std::make_shared<ClientMetadataHandle>(std::move(metadata));
        // Handle write failure. In observability mode, if write fails and
        // failure_mode_allow is true, we fail-open and continue the call.
        auto write_promise = Map(
            ext_proc_call->SendClientInitialMetadataRequest(
                shared_metadata,
                ext_proc_filter->default_authority_.as_string_view()),
            [failure_mode_allow =
                 ext_proc_filter->config_->failure_mode_allow.value_or(false),
             ext_proc_call](absl::Status status) -> absl::Status {
              if (!status.ok()) {
                if (failure_mode_allow) {
                  GRPC_TRACE_LOG(ext_proc_filter, INFO)
                      << "ExtProc: Initial metadata write failed, but "
                         "failure_mode_allow=true. Proceeding with fail-open "
                         "behavior. Error: "
                      << status;
                  return absl::OkStatus();
                }
                if (ext_proc_call->IsStreamClosed() &&
                    !ext_proc_call->GetStreamStatus().ok()) {
                  return ext_proc_call->GetStreamStatus();
                }
              }
              return status;
            });
        // After the write attempt (successful or failed-open), we immediately
        // start the child call to the backend server. We do NOT wait for
        // responses from ext_proc.
        return TrySeq(
            std::move(write_promise),
            [handler, ext_proc_filter, ext_proc_call = std::move(ext_proc_call),
             shared_metadata = std::move(shared_metadata),
             start_time]() mutable -> absl::AnyInvocable<Poll<absl::Status>()> {
              ext_proc_filter->RecordClientHeadersDuration(
                  (Timestamp::Now() - start_time).seconds());
              CallInitiator initiator = ext_proc_filter->MakeChildCall(
                  std::move(*shared_metadata), handler.arena()->Ref());
              handler.AddChildCall(initiator);
              // Spawn background task to handle server-to-client path
              // (responses).
              initiator.SpawnInfallible(
                  "server_to_client",
                  [handler, initiator, ext_proc_filter,
                   ext_proc_call = ext_proc_call->Ref()]() mutable {
                    GRPC_TRACE_LOG(ext_proc_filter, INFO)
                        << "ExtProc: server_to_client task started";
                    return initiator.CancelIfFails(
                        ext_proc_filter->ServerToClientCall(
                            handler, initiator, std::move(ext_proc_call)));
                  });
              // Continue with forwarding client messages (request body).
              return ClientToServerMessages(handler, initiator, ext_proc_filter,
                                            std::move(ext_proc_call),
                                            /*attributes=*/nullptr);
            });
      });
}

absl::AnyInvocable<Poll<absl::Status>()>
ExtProcFilter::ClientToServerCallNormalMode(
    CallHandler handler, RefCountedPtr<ExtProcCall> ext_proc_call) {
  Timestamp start_time = Timestamp::Now();
  return TrySeq(
      handler.PullClientInitialMetadata(),
      [ext_proc_filter = RefAsSubclass<ExtProcFilter>(),
       ext_proc_call](ClientMetadataHandle metadata) mutable {
        GRPC_TRACE_LOG(ext_proc_filter, INFO)
            << "ExtProc: Client initial metadata received:\n"
            << metadata->DebugString();
        auto shared_metadata =
            std::make_shared<ClientMetadataHandle>(std::move(metadata));
        return Seq(
            ext_proc_call->SendClientInitialMetadataRequest(
                shared_metadata,
                ext_proc_filter->default_authority_.as_string_view()),
            [ext_proc_call, shared_metadata](absl::Status status) mutable
                -> absl::StatusOr<ClientMetadataHandle> {
              if (!status.ok()) {
                if (ext_proc_call->IsFailOpenAllowed()) {
                  GRPC_TRACE_LOG(ext_proc_filter, INFO)
                      << "ExtProc: Client initial metadata send failed, but "
                         "fail-open is allowed. Error: "
                      << status;
                  return std::move(*shared_metadata);
                }
                return ext_proc_call->IsStreamClosed()
                           ? ext_proc_call->GetStreamStatus()
                           : status;
              }
              return std::move(*shared_metadata);
            });
      },
      [handler, ext_proc_filter = RefAsSubclass<ExtProcFilter>(),
       ext_proc_call = std::move(ext_proc_call),
       start_time](ClientMetadataHandle metadata) mutable {
        return TrySeq(
            ext_proc_call->request_headers_latch().Wait(),
            // Process the response from ext_proc.
            [ext_proc_filter,
             metadata = std::move(metadata)](ExtProcResponse response) mutable
                -> absl::StatusOr<ClientMetadataHandle> {
              // Apply header mutations if returned by ext_proc.
              if (const auto* headers =
                      std::get_if<ExtProcResponse::RequestHeaders>(
                          &response.response);
                  headers != nullptr) {
                const auto* rules =
                    ext_proc_filter->config_->mutation_rules.has_value()
                        ? &ext_proc_filter->config_->mutation_rules.value()
                        : nullptr;
                auto status =
                    ApplyHeaderMutations(headers->mutation, rules, *metadata);
                if (!status.ok()) return status;
              }
              return std::move(metadata);
            },
            // Handle the result of response processing.
            [handler, ext_proc_filter = std::move(ext_proc_filter),
             ext_proc_call = std::move(ext_proc_call),
             start_time](ClientMetadataHandle metadata) mutable
                -> absl::AnyInvocable<Poll<absl::Status>()> {
              ext_proc_filter->RecordClientHeadersDuration(
                  (Timestamp::Now() - start_time).seconds());
              CallInitiator initiator = ext_proc_filter->MakeChildCall(
                  std::move(metadata), handler.arena()->Ref());
              handler.AddChildCall(initiator);
              // Spawn background task to handle server-to-client path.
              initiator.SpawnInfallible(
                  "server_to_client",
                  [handler, initiator, ext_proc_filter,
                   ext_proc_call = ext_proc_call->Ref()]() mutable {
                    GRPC_TRACE_LOG(ext_proc_filter, INFO)
                        << "ExtProc: server_to_client task started";
                    return initiator.CancelIfFails(
                        ext_proc_filter->ServerToClientCall(
                            handler, initiator, std::move(ext_proc_call)));
                  });
              return ClientToServerMessages(handler, initiator, ext_proc_filter,
                                            std::move(ext_proc_call),
                                            /*attributes=*/nullptr);
            });
      });
}

absl::AnyInvocable<Poll<absl::Status>()>
ExtProcFilter::ClientToServerCallNonProcessingMode(
    CallHandler handler, RefCountedPtr<ExtProcCall> ext_proc_call) {
  return TrySeq(
      handler.PullClientInitialMetadata(),
      [handler, ext_proc_filter = RefAsSubclass<ExtProcFilter>(),
       ext_proc_call](ClientMetadataHandle metadata) mutable
          -> absl::AnyInvocable<Poll<absl::Status>()> {
        GRPC_TRACE_LOG(ext_proc_filter, INFO)
            << "ExtProc: Client initial metadata received (non-processing):\n"
            << metadata->DebugString();
        const auto& processing_mode =
            *ext_proc_filter->config_->processing_mode;
        ::google_protobuf_Struct* attributes = nullptr;
        if (processing_mode.send_request_body &&
            !ext_proc_filter->config_->request_attributes.empty()) {
          auto* arena = handler.arena()->New<upb::Arena>();
          attributes = CreateExtProcAttributesProtoStruct(
              arena->ptr(), ext_proc_filter->config_->request_attributes,
              *metadata, ext_proc_filter->default_authority_.as_string_view());
        }
        CallInitiator initiator = ext_proc_filter->MakeChildCall(
            std::move(metadata), handler.arena()->Ref());
        handler.AddChildCall(initiator);
        // Spawn background task to handle server-to-client path.
        initiator.SpawnInfallible(
            "server_to_client",
            [handler, initiator, ext_proc_filter, ext_proc_call]() mutable {
              GRPC_TRACE_LOG(ext_proc_filter, INFO)
                  << "ExtProc: server_to_client task started";
              return initiator.CancelIfFails(
                  ext_proc_filter->ServerToClientCall(handler, initiator,
                                                      ext_proc_call));
            });
        return ClientToServerMessages(handler, initiator, ext_proc_filter,
                                      std::move(ext_proc_call), attributes);
      });
}

// Handles the response path (Server to Client).
// This function sets up a pipeline to process server initial metadata,
// response messages, and server trailing metadata, potentially intercepting
// and mutating them via the ext_proc server.
//
// It also watches for ext_proc stream errors and aborts the call if a failure
// occurs and fail-open is not allowed.
absl::AnyInvocable<Poll<absl::Status>()> ExtProcFilter::ServerToClientCall(
    CallHandler handler, CallInitiator initiator,
    RefCountedPtr<ExtProcCall> ext_proc_call) {
  GRPC_TRACE_LOG(ext_proc_filter, INFO)
      << "ExtProcCall " << ext_proc_call.get() << " ServerToClientCall started";
  // Pipeline for normal response processing.
  auto response_pipeline = Seq(
      // Phase 1: Process initial metadata and response messages.
      TrySeq(
          // Step A: Pull Server Initial Metadata from the backend server.
          initiator.PullServerInitialMetadata(),
          [handler, initiator, ext_proc_filter = RefAsSubclass<ExtProcFilter>(),
           ext_proc_call](std::optional<ServerMetadataHandle> md) mutable {
            const bool has_md = md.has_value();
            return If(
                has_md,
                [handler, initiator, ext_proc_filter, ext_proc_call,
                 md = std::move(md)]() mutable {
                  auto shared_md =
                      std::make_shared<ServerMetadataHandle>(std::move(*md));
                  return TrySeq(
                      // Step 1: Intercept, send to ext_proc, and apply
                      // mutations to Server Initial Metadata.
                      ServerInitialMetadata(handler, initiator, ext_proc_filter,
                                            ext_proc_call, shared_md),
                      // Step 2: Intercept and process Server-to-Client Messages
                      // (body).
                      [handler, initiator, ext_proc_call]() mutable {
                        return ServerToClientMessages(handler, initiator,
                                                      ext_proc_call);
                      });
                },
                []() {
                  // Trailers-Only response: Bypasses both headers and messages!
                  return absl::OkStatus();
                });
          }),
      // Phase 2: Process trailing metadata.
      // This runs after Phase 1 (headers and messages) is complete.
      [handler, initiator, ext_proc_filter = RefAsSubclass<ExtProcFilter>(),
       ext_proc_call](absl::Status status) mutable {
        if (!status.ok()) {
          // If Phase 1 failed, we propagate the error.
          return absl::AnyInvocable<Poll<absl::Status>()>(
              [status]() -> Poll<absl::Status> { return status; });
        }
        // Phase 1 succeeded. Pull and process trailing metadata.
        return absl::AnyInvocable<Poll<absl::Status>()>(Seq(
            initiator.PullServerTrailingMetadata(),
            [handler, initiator, ext_proc_filter,
             ext_proc_call](ServerMetadataHandle md) mutable {
              auto shared_md =
                  std::make_shared<ServerMetadataHandle>(std::move(md));
              // Intercept, send to ext_proc, and apply mutations to
              // Trailing Metadata.
              return ServerTrailingMetadata(handler, initiator, ext_proc_filter,
                                            ext_proc_call, shared_md);
            }));
      });
  // Monitor the ext_proc stream for errors.
  // If the ext_proc stream fails and fail-open is NOT allowed, we abort the
  // call.
  auto watch_error = Seq(
      ext_proc_call->WaitForStreamStatus(),
      [ext_proc_call](
          absl::Status status) -> absl::AnyInvocable<Poll<absl::Status>()> {
        GRPC_TRACE_LOG(ext_proc_filter, INFO)
            << "watch_error stream_status: " << status
            << ", failure_mode_allow: "
            << (ext_proc_call->config()->failure_mode_allow.has_value()
                    ? (*ext_proc_call->config()->failure_mode_allow ? "true"
                                                                    : "false")
                    : "unset");
        if (!status.ok() &&
            !ext_proc_call->config()->failure_mode_allow.value_or(false)) {
          return [status]() -> Poll<absl::Status> { return status; };
        }
        return []() -> Poll<absl::Status> {
          GRPC_TRACE_LOG(ext_proc_filter, INFO)
              << "watch_error returning Pending";
          return Pending{};
        };
      });
  // Race the response pipeline against the error watcher.
  // If watch_error returns an error, it will win the race and abort the
  // pipeline.
  auto run_pipeline =
      PrioritizedRace(std::move(watch_error), std::move(response_pipeline));
  return [handler, initiator, ext_proc_call,
          promise = std::move(run_pipeline)]() mutable -> Poll<absl::Status> {
    auto p = promise();
    if (auto* status = p.value_if_ready()) {
      GRPC_TRACE_LOG(ext_proc_filter, INFO)
          << "ExtProcCall " << ext_proc_call.get()
          << " ServerToClientCall finished. status=" << *status;
      // Handle failures in the pipeline (either from the response path or the
      // error watcher).
      if (!status->ok()) {
        GRPC_TRACE_LOG(ext_proc_filter, INFO)
            << "ExtProcCall " << ext_proc_call.get()
            << " ServerToClientCall failed: " << *status;
        // Push error trailers to the parent call (client).
        auto error_md = CancelledServerMetadataFromStatus(*status);
        GRPC_TRACE_LOG(ext_proc_filter, INFO)
            << "ExtProcCall " << ext_proc_call.get()
            << ": Pushing server trailing metadata downstream (error)";
        handler.SpawnPushServerTrailingMetadata(std::move(error_md));
        // Cancel the child call to the backend server.
        initiator.Cancel();
        // Close the ext_proc stream.
        ext_proc_call->CloseStream();
      }
      return *status;
    }
    return Pending{};
  };
}

void ExtProcFilter::InterceptCall(UnstartedCallHandler unstarted_call_handler) {
  if (!IsProcessingEnabled(config_->processing_mode)) {
    PassThrough(std::move(unstarted_call_handler));
    return;
  }
  CallHandler handler = Consume(std::move(unstarted_call_handler));
  handler.SpawnGuarded(
      "ext_proc_call",
      [handler, ext_proc_filter = RefAsSubclass<ExtProcFilter>()]() mutable
          -> ArenaPromise<absl::Status> {
        GRPC_TRACE_LOG(ext_proc_filter, INFO)
            << "ExtProc: InterceptCall promise chain start";
        auto transport = ext_proc_filter->channel()->transport();
        if (transport == nullptr) {
          return ArenaPromise<absl::Status>([]() -> Poll<absl::Status> {
            return absl::InternalError("ExtProc channel transport is null");
          });
        }
        auto ext_proc_call = MakeRefCounted<ExtProcCall>(
            std::move(transport), ext_proc_filter->config_,
            ext_proc_filter->event_engine_);
        return ArenaPromise<absl::Status>(If(
            !ext_proc_filter->config_->processing_mode->send_request_headers,
            [handler, ext_proc_filter, ext_proc_call]() mutable {
              return ext_proc_filter->ClientToServerCallNonProcessingMode(
                  handler, std::move(ext_proc_call));
            },
            [handler, ext_proc_filter, ext_proc_call]() mutable {
              return If(
                  ext_proc_filter->config_->observability_mode,
                  [ext_proc_filter, handler, ext_proc_call]() mutable {
                    return ext_proc_filter->ClientToServerObservabilityMode(
                        handler, std::move(ext_proc_call));
                  },
                  [handler, ext_proc_filter, ext_proc_call]() mutable {
                    return ext_proc_filter->ClientToServerCallNormalMode(
                        handler, std::move(ext_proc_call));
                  });
            }));
      });
}

}  // namespace grpc_core
