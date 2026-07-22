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
#include "src/core/xds/xds_client/streaming_call_promise_wrapper.h"
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
  ExtProcCall(RefCountedPtr<ExtProcFilter> ext_proc_filter,
              RefCountedPtr<XdsTransportFactory::XdsTransport> transport,
              CallHandler handler)
      : ext_proc_filter_(std::move(ext_proc_filter)),
        transport_(std::move(transport)),
        handler_(handler) {
    const char* method = "/envoy.service.ext_proc.v3.ExternalProcessor/Process";
    streaming_call_ = MakeRefCounted<StreamingCallPromiseWrapper>(
        *transport_, method, std::make_unique<StreamEventHandler>(WeakRef()),
        /*wait_for_ready=*/false);
    streaming_call_->StartRecvMessage();
  }

  ~ExtProcCall() override {
    if (ext_proc_filter_->config_->deferred_close_timeout != Duration::Zero() &&
        ext_proc_filter_->config_->observability_mode) {
      if (ext_proc_filter_->event_engine_ != nullptr) {
        ext_proc_filter_->event_engine_->RunAfter(
            ext_proc_filter_->config_->deferred_close_timeout,
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

  RefCountedPtr<const Config> config() const {
    return ext_proc_filter_->config_;
  }

  bool IsFirstMessageOnStream() {
    return is_first_message_on_ext_proc_stream_.exchange(
        false, std::memory_order_acq_rel);
  }

  bool IsFailOpenAllowed() const {
    const bool allow =
        ext_proc_filter_->config_->failure_mode_allow.value_or(false);
    if (ext_proc_filter_->config_->observability_mode) return allow;
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

  absl::AnyInvocable<Poll<absl::Status>()> Call();

 private:
  absl::AnyInvocable<Poll<absl::Status>()>
  SendAndProcessServerHeadersNormalMode(
      std::shared_ptr<ServerMetadataHandle> metadata, bool end_of_stream,
      absl::AnyInvocable<void(ServerMetadataHandle)> push_fn);

  absl::AnyInvocable<Poll<absl::Status>()> ServerInitialMetadataNormalMode(
      std::shared_ptr<ServerMetadataHandle> metadata);

  // Handles server trailing metadata in normal mode for "trailers-only"
  // responses (when an RPC terminates immediately without sending initial
  // metadata or response body).
  // Since it is trailers-only, it sends a ServerHeaders request to the external
  // processor (with end_of_stream=true), waits for the response, applies
  // mutations or handles immediate responses, and pushes the final metadata
  // downstream.
  absl::AnyInvocable<Poll<absl::Status>()>
  ServerTrailingMetadataTrailersOnlyNormalMode(
      std::shared_ptr<ServerMetadataHandle> metadata);

  // Sends server initial metadata to ext_proc in observability mode.
  auto ServerInitialMetadataObservabilityMode(
      std::shared_ptr<ServerMetadataHandle> metadata);

  absl::AnyInvocable<Poll<absl::Status>()> ServerInitialMetadata(
      std::shared_ptr<ServerMetadataHandle> metadata);

  auto ServerToClientMessagesObservabilityMode();

  absl::AnyInvocable<Poll<absl::Status>()>
  SendServerToClientMessagesToExtProcServer();

  absl::AnyInvocable<Poll<absl::Status>()>
  ReadServerToClientMessagesFromExtProcServer();

  absl::AnyInvocable<Poll<absl::Status>()> ServerToClientMessagesNormalMode();

  absl::AnyInvocable<Poll<absl::Status>()> ServerToClientMessages();

  absl::AnyInvocable<Poll<absl::Status>()>
  ReadServerTrailingMetadataFromExtProcServer(
      std::shared_ptr<ServerMetadataHandle> metadata, Timestamp start_time);

  absl::AnyInvocable<Poll<absl::Status>()> ServerTrailingMetadataNormalMode(
      std::shared_ptr<ServerMetadataHandle> metadata);

  absl::AnyInvocable<Poll<absl::Status>()>
  ServerTrailingMetadataObservabilityMode(
      std::shared_ptr<ServerMetadataHandle> metadata);

  absl::AnyInvocable<Poll<absl::Status>()>
  ServerTrailingMetadataNonProcessingMode(
      std::shared_ptr<ServerMetadataHandle> metadata);

  // Helper that checks if the external processor stream is already closed or
  // half-closed.
  // If it closed with an error and the configuration does NOT allow fail-open
  // (server_fail_open_allowed=false), returns a promise resolving to that
  // error. If it closed cleanly, or closed with error but fail-open IS allowed,
  // falls back to pushing the unmutated trailing metadata downstream
  // immediately. Returns std::nullopt if the stream is active and processing
  // should continue.
  absl::optional<absl::AnyInvocable<Poll<absl::Status>()>>
  MaybeHandleClosedStream(std::shared_ptr<ServerMetadataHandle> metadata);

  // Orchestrates the server trailing metadata step when the RPC is
  // "trailers-only". (i.e. backend immediately sent trailing metadata without
  // any preceding body or initial metadata).
  absl::AnyInvocable<Poll<absl::Status>()> ServerTrailingMetadataTrailersOnly(
      std::shared_ptr<ServerMetadataHandle> metadata);

  // Orchestrates the server trailing metadata step for a normal RPC (one that
  // has
  // sent initial metadata and/or response body before finishing).
  absl::AnyInvocable<Poll<absl::Status>()> ServerTrailingMetadataNormal(
      std::shared_ptr<ServerMetadataHandle> metadata);

  // Main dispatcher function for the ServerTrailingMetadata filter interceptor
  // step. Distinguishes between "trailers-only" RPCs and normal RPCs and routes
  // accordingly.
  absl::AnyInvocable<Poll<absl::Status>()> ServerTrailingMetadata(
      std::shared_ptr<ServerMetadataHandle> metadata);

  // Intercepts and processes client-to-server messages.
  // Forwards client messages to backend without processing when request body
  // processing is disabled or ext_proc stream is closed.
  absl::AnyInvocable<Poll<absl::Status>()>
  ClientToServerMessagesNonProcessingMode();

  // Handles client-to-server messages in observability mode
  absl::AnyInvocable<Poll<absl::Status>()>
  ClientToServerMessagesObservabilityMode(::google_protobuf_Struct* attributes);

  absl::AnyInvocable<Poll<absl::Status>()> ClientToSidestreamNormalMode(
      ::google_protobuf_Struct* attributes);

  // Handles processing responses from the external processing server
  // (sidestream) and forwarding the (possibly mutated) request body to the
  // backend server.
  absl::AnyInvocable<Poll<absl::Status>()> SidestreamToServerNormalMode();

  absl::AnyInvocable<Poll<absl::Status>()> ClientToServerMessagesNormalMode(
      ::google_protobuf_Struct* attributes);

  absl::AnyInvocable<Poll<absl::Status>()> ClientToServerMessages(
      ::google_protobuf_Struct* attributes);

  absl::AnyInvocable<Poll<absl::Status>()> ClientToServerObservabilityMode();

  absl::AnyInvocable<Poll<absl::Status>()> ClientToServerCallNormalMode();

  absl::AnyInvocable<Poll<absl::Status>()>
  ClientToServerCallNonProcessingMode();

  absl::AnyInvocable<Poll<absl::Status>()> ServerToClientCall();

  auto SendClientInitialMetadataRequest(
      std::shared_ptr<ClientMetadataHandle> metadata,
      absl::string_view default_authority);

  auto SendServerInitialMetadataRequest(
      std::shared_ptr<ServerMetadataHandle> metadata,
      bool end_of_stream = false);

  auto SendServerMessageRequest(const MessageHandle& message);

  auto SendServerTrailingMetadataRequest(
      std::shared_ptr<ServerMetadataHandle> metadata);

  auto SendClientMessageRequest(const MessageHandle& message,
                                bool end_of_stream,
                                bool end_of_stream_without_message,
                                ::google_protobuf_Struct* attributes);

  // Event handler callback for the ext_proc stream. Wraps a weak reference
  // to ExtProcCall to safely dispatch asynchronous stream lifecycle events
  // (message sent, message received, stream closed/status received) back to
  // the owning ExtProcCall instance without preventing destruction or
  // causing cyclic reference memory leaks.
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
    const auto& processing_mode = *ext_proc_filter_->config_->processing_mode;
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
    if (ext_proc_filter_->config_->observability_mode) {
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
    const auto& processing_mode = *ext_proc_filter_->config_->processing_mode;
    Match(
        (*parsed_response).response,
        [&](const ExtProcResponse::ImmediateResponse&) {
          if (ext_proc_filter_->config_->disable_immediate_response ||
              !server_trailers_sent()) {
            auto error = absl::InternalError(
                ext_proc_filter_->config_->disable_immediate_response
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
    const bool must_drain =
        !ext_proc_filter_->config_->observability_mode &&
        (ext_proc_filter_->config_->processing_mode->send_request_body ||
         ext_proc_filter_->config_->processing_mode->send_response_body);
    const bool drain_requested =
        drain_requested_.load(std::memory_order_relaxed);
    if (status.ok()) {
      if (must_drain && !drain_requested) {
        status = absl::InternalError("Stream closed cleanly without drain");
      } else if (has_outstanding_messages &&
                 !ext_proc_filter_->config_->observability_mode) {
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
  RefCountedPtr<ExtProcFilter> ext_proc_filter_;
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
  CallHandler handler_;
  CallInitiator initiator_;
  RefCountedPtr<StreamingCallPromiseWrapper> streaming_call_;
};

auto ExtProcFilter::ExtProcCall::SendClientInitialMetadataRequest(
    std::shared_ptr<ClientMetadataHandle> metadata,
    absl::string_view default_authority) {
  const bool is_first_message = IsFirstMessageOnStream();
  return SendMessage([config = ext_proc_filter_->config_, metadata,
                      default_authority = std::string(default_authority),
                      is_first_message]() {
    GRPC_TRACE_LOG(ext_proc_filter, INFO)
        << "ExtProc: Sending client initial metadata";
    upb::Arena arena;
    auto* header_attributes = CreateExtProcAttributesProtoStruct(
        arena.ptr(), config->request_attributes, **metadata, default_authority);
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

auto ExtProcFilter::ExtProcCall::SendServerInitialMetadataRequest(
    std::shared_ptr<ServerMetadataHandle> metadata, bool end_of_stream) {
  const bool is_first_message = IsFirstMessageOnStream();
  return SendMessage([config = ext_proc_filter_->config_, metadata,
                      is_first_message, end_of_stream]() {
    std::optional<ExtProcProcessingMode> processing_mode;
    if (is_first_message) {
      processing_mode = config->processing_mode;
    }
    upb::Arena arena;
    return CreateExtProcServerHeadersRequest(
        arena.ptr(), metadata->get(), config->forwarding_allowed_headers,
        config->forwarding_disallowed_headers,
        /*attributes=*/nullptr, config->observability_mode, processing_mode,
        end_of_stream);
  });
}

auto ExtProcFilter::ExtProcCall::SendServerMessageRequest(
    const MessageHandle& message) {
  if (!ext_proc_filter_->config_->observability_mode) {
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

auto ExtProcFilter::ExtProcCall::SendServerTrailingMetadataRequest(
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
                  ext_proc_call->config()->observability_mode, processing_mode);
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

auto ExtProcFilter::ExtProcCall::SendClientMessageRequest(
    const MessageHandle& message, bool end_of_stream,
    bool end_of_stream_without_message, ::google_protobuf_Struct* attributes) {
  std::string message_bytes;
  if (message != nullptr) {
    message_bytes = message->payload()->JoinIntoString();
  }
  if (!ext_proc_filter_->config_->observability_mode) {
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

absl::AnyInvocable<Poll<absl::Status>()>
ExtProcFilter::ExtProcCall::ServerInitialMetadataNormalMode(
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
      drain_requested(),
      [self = WeakRefAsSubclass<ExtProcCall>(), metadata]() mutable {
        GRPC_TRACE_LOG(ext_proc_filter, INFO)
            << "ExtProc: Drain active before sending Server Initial Metadata, "
               "blocking propagation";
        return Map(
            self->WaitForStreamStatus(),
            [self, metadata](absl::Status status) mutable -> absl::Status {
              GRPC_TRACE_LOG(ext_proc_filter, INFO)
                  << "ExtProc: Server Initial Metadata Drain complete "
                     "(pre-existing). Status: "
                  << status;
              if (!self->IsStreamClosedCleanly() &&
                  !self->IsFailOpenAllowed()) {
                return status;
              }
              self->handler_.SpawnPushServerInitialMetadata(
                  std::move(*metadata));
              return absl::OkStatus();
            });
      },
      [self = WeakRefAsSubclass<ExtProcCall>(), metadata,
       start_time]() mutable {
        return self->SendAndProcessServerHeadersNormalMode(
            metadata, /*end_of_stream=*/false,
            [self, start_time](ServerMetadataHandle metadata) mutable {
              self->ext_proc_filter_->RecordServerHeadersDuration(
                  (Timestamp::Now() - start_time).seconds());
              self->handler_.SpawnPushServerInitialMetadata(
                  std::move(metadata));
            });
      });
}

absl::AnyInvocable<Poll<absl::Status>()>
ExtProcFilter::ExtProcCall::SendAndProcessServerHeadersNormalMode(
    std::shared_ptr<ServerMetadataHandle> metadata, bool end_of_stream,
    absl::AnyInvocable<void(ServerMetadataHandle)> push_fn) {
  return Seq(
      SendServerInitialMetadataRequest(metadata, end_of_stream),
      [self = WeakRefAsSubclass<ExtProcCall>(), metadata,
       push_fn = std::move(push_fn)](absl::Status status) mutable
          -> absl::AnyInvocable<Poll<absl::Status>()> {
        // Handle failure to write the server metadata to the external
        // processor.
        if (!status.ok()) {
          // If the write fails but fail-open behavior is allowed, propagate the
          // metadata downstream unmutated and bypass waiting for a response.
          if (self->IsFailOpenAllowed()) {
            GRPC_TRACE_LOG(ext_proc_filter, INFO)
                << "ExtProc: Server initial metadata send failed, but "
                   "fail-open is allowed. Error: "
                << status;
            push_fn(std::move(*metadata));
            return []() -> Poll<absl::Status> { return absl::OkStatus(); };
          }
          // If fail-open is disabled, fail the RPC with the closed stream error
          // status.
          absl::Status err =
              self->IsStreamClosed() ? self->GetStreamStatus() : status;
          return [err]() -> Poll<absl::Status> { return err; };
        }
        return Map(
            // Wait for response headers (which will contain the external
            // processor's decision on our ServerHeaders request).
            self->response_headers_latch().Wait(),
            [metadata, self, push_fn = std::move(push_fn)](
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
                    self->config()->mutation_rules.has_value()
                        ? &self->config()->mutation_rules.value()
                        : nullptr;
                // Apply header mutations from the external processor's
                // response.
                status =
                    ApplyHeaderMutations(headers->mutation, rules, **metadata);
              }
              // If an error occurred while waiting for or processing the
              // response, check failure mode configuration. Unless fail-open
              // is allowed, fail the stream with error status.
              if (!status.ok() && !self->IsFailOpenAllowed()) {
                return self->IsStreamClosed() ? self->GetStreamStatus()
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

absl::AnyInvocable<Poll<absl::Status>()>
ExtProcFilter::ExtProcCall::ServerTrailingMetadataTrailersOnlyNormalMode(
    std::shared_ptr<ServerMetadataHandle> metadata) {
  GRPC_TRACE_LOG(ext_proc_filter, INFO)
      << "ExtProc: ServerTrailingMetadataTrailersOnlyNormalMode started";
  Timestamp start_time = Timestamp::Now();
  // If a drain has been requested, we bypass sending the server trailing
  // metadata to the external processor. Instead, we wait for the ext_proc
  // stream to close (drain complete) before propagating the metadata
  // downstream, subject to fail-open/fail-closed policies (trailers-only case).
  return If(
      drain_requested(),
      [self = WeakRefAsSubclass<ExtProcCall>(), metadata]() mutable {
        GRPC_TRACE_LOG(ext_proc_filter, INFO)
            << "ExtProc: Drain active before sending Server Trailing Metadata "
               "(Trailers Only), blocking propagation";
        return Map(
            self->WaitForStreamStatus(),
            [self, metadata](absl::Status status) mutable -> absl::Status {
              GRPC_TRACE_LOG(ext_proc_filter, INFO)
                  << "ExtProc: Server Trailing Metadata (Trailers Only) Drain "
                     "complete (pre-existing). Status: "
                  << status;
              if (!self->IsStreamClosedCleanly() &&
                  !self->IsFailOpenAllowed()) {
                return status;
              }
              self->handler_.SpawnPushServerTrailingMetadata(
                  std::move(*metadata));
              return absl::OkStatus();
            });
      },
      [self = WeakRefAsSubclass<ExtProcCall>(), metadata,
       start_time]() mutable {
        // Send the trailers-only metadata as ServerHeaders (with
        // end_of_stream=true).
        return self->SendAndProcessServerHeadersNormalMode(
            metadata, /*end_of_stream=*/true,
            [self, start_time](ServerMetadataHandle metadata) mutable {
              self->ext_proc_filter_->RecordServerHeadersDuration(
                  (Timestamp::Now() - start_time).seconds());
              self->handler_.SpawnPushServerTrailingMetadata(
                  std::move(metadata));
            });
      });
}

// Sends server initial metadata to ext_proc in observability mode.
auto ExtProcFilter::ExtProcCall::ServerInitialMetadataObservabilityMode(
    std::shared_ptr<ServerMetadataHandle> metadata) {
  GRPC_TRACE_LOG(ext_proc_filter, INFO)
      << "ExtProc: ServerInitialMetadataObservabilityMode pulled. metadata: "
      << (*metadata)->DebugString();
  Timestamp start_time = Timestamp::Now();
  return Map(
      SendServerInitialMetadataRequest(metadata,
                                       /*end_of_stream=*/is_trailers_only()),
      [self = WeakRefAsSubclass<ExtProcCall>(), metadata,
       start_time](absl::Status status) mutable -> absl::Status {
        // If write failed and fail-open is not allowed, fail closed unless
        // clean stream closure occurred.
        if (!status.ok() && !self->IsFailOpenAllowed()) {
          if (self->IsStreamClosedCleanly()) {
            GRPC_TRACE_LOG(ext_proc_filter, INFO)
                << "ExtProc: Ignored server initial metadata send failure "
                   "in observability mode due to clean close: "
                << status;
          } else {
            if (self->IsStreamClosed() && !self->GetStreamStatus().ok()) {
              return self->GetStreamStatus();
            }
            return status;
          }
        }
        // Immediately push initial metadata (or trailers-only) downstream.
        if (self->is_trailers_only()) {
          self->handler_.SpawnPushServerTrailingMetadata(std::move(*metadata));
        } else {
          self->ext_proc_filter_->RecordServerHeadersDuration(
              (Timestamp::Now() - start_time).seconds());
          self->handler_.SpawnPushServerInitialMetadata(std::move(*metadata));
        }
        return absl::OkStatus();
      });
}

absl::AnyInvocable<Poll<absl::Status>()>
ExtProcFilter::ExtProcCall::ServerInitialMetadata(
    std::shared_ptr<ServerMetadataHandle> metadata) {
  const bool send_headers = config()->processing_mode->send_response_headers &&
                            !IsStreamClosed() && !ext_proc_stream_half_closed();
  if (!send_headers) {
    return [self = WeakRefAsSubclass<ExtProcCall>(), metadata]() mutable {
      if (self != nullptr && self->IsStreamClosed() &&
          !self->IsStreamClosedCleanly() && !self->IsFailOpenAllowed()) {
        return self->GetStreamStatus();
      }
      GRPC_TRACE_LOG(ext_proc_filter, INFO)
          << "ExtProc: ServerInitialMetadataNonProcessingMode metadata: "
          << (*metadata)->DebugString();
      self->handler_.SpawnPushServerInitialMetadata(std::move(*metadata));
      return absl::OkStatus();
    };
  } else if (config()->observability_mode) {
    return ServerInitialMetadataObservabilityMode(std::move(metadata));
  } else {
    return ServerInitialMetadataNormalMode(std::move(metadata));
  }
}

// Forwards server-to-client messages in observability mode.
auto ExtProcFilter::ExtProcCall::ServerToClientMessagesObservabilityMode() {
  GRPC_TRACE_LOG(ext_proc_filter, INFO)
      << "ExtProc: ServerToClientMessagesObservabilityMode started, "
      << "stream_closed=" << IsStreamClosed();
  return ForEach(
      MessagesFrom(initiator_),
      [self = WeakRefAsSubclass<ExtProcCall>()](MessageHandle message) mutable {
        GRPC_TRACE_LOG(ext_proc_filter, INFO)
            << "ExtProc: ServerToClientMessagesObservabilityMode "
               "processing message, stream_closed="
            << self->IsStreamClosed();
        return Map(
            If(
                !self->IsStreamClosed(),
                [self, &message]() {
                  // Asynchronously transmit the server response body to
                  // ext_proc for observation.
                  return self->SendServerMessageRequest(message);
                },
                []() -> absl::Status { return absl::OkStatus(); }),
            [self, message = std::move(message)](
                absl::Status status) mutable -> absl::Status {
              // If sending to ext_proc failed and fail-open is not allowed,
              // check if stream closed cleanly.
              if (!status.ok() && !self->IsFailOpenAllowed()) {
                if (self->IsStreamClosedCleanly()) {
                  GRPC_TRACE_LOG(ext_proc_filter, INFO)
                      << "ExtProc: Ignored server message send failure in "
                         "observability mode due to clean close: "
                      << status;
                } else {
                  return status;
                }
              }
              // Immediately forward the unmutated message downstream.
              self->handler_.SpawnPushMessage(std::move(message));
              return absl::OkStatus();
            });
      });
}

absl::AnyInvocable<Poll<absl::Status>()>
ExtProcFilter::ExtProcCall::SendServerToClientMessagesToExtProcServer() {
  GRPC_TRACE_LOG(ext_proc_filter, INFO)
      << "ExtProc: SendServerToClientMessagesToExtProcServer started";
  return Seq(
      ForEach(
          MessagesFrom(initiator_),
          [self = WeakRefAsSubclass<ExtProcCall>()](
              MessageHandle message) mutable {
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
                self->drain_requested(),
                [self, shared_message]() mutable {
                  GRPC_TRACE_LOG(ext_proc_filter, INFO)
                      << "ExtProc: Drain active, blocking S2C Write Loop";
                  return Map(
                      // Block forwarding data plane messages until the external
                      // processor stream has fully closed and set its final
                      // status. Once resolved, we check if we should fail open
                      // or fail closed before resuming message delivery.
                      self->WaitForStreamStatus(),
                      [self, shared_message](
                          absl::Status status) mutable -> absl::Status {
                        GRPC_TRACE_LOG(ext_proc_filter, INFO)
                            << "ExtProc: S2C Drain complete, resuming S2C "
                               "bypass. Status: "
                            << status;
                        auto message = std::move(*shared_message);
                        if (!self->IsStreamClosedCleanly() &&
                            !self->IsFailOpenAllowed()) {
                          return status;
                        }
                        self->handler_.SpawnPushMessage(std::move(message));
                        return absl::OkStatus();
                      });
                },
                [self, shared_message]() mutable {
                  const bool send_message =
                      self->config()->processing_mode->send_response_body &&
                      !self->IsStreamClosed() &&
                      !self->ext_proc_stream_half_closed();
                  return If(
                      send_message,
                      [self, shared_message]() mutable {
                        return Map(
                            self->SendServerMessageRequest(*shared_message),
                            [self, shared_message](
                                absl::Status status) mutable -> absl::Status {
                              auto message = std::move(*shared_message);
                              if (!status.ok() || self->IsStreamClosed()) {
                                // If not cleanly closed and fail-open is not
                                // allowed, return error status immediately.
                                if (!self->IsStreamClosedCleanly() &&
                                    !self->IsFailOpenAllowed()) {
                                  return self->IsStreamClosed()
                                             ? self->GetStreamStatus()
                                             : status;
                                }
                                // Otherwise, bypass ext_proc and push message
                                // directly to client.
                                self->handler_.SpawnPushMessage(
                                    std::move(message));
                              }
                              return absl::OkStatus();
                            });
                      },
                      // When message processing is disabled or the external
                      // processor stream is closed, bypass ext_proc and forward
                      // the message directly to the client (unless stream error
                      // requires failing closed).
                      [self, shared_message]() mutable {
                        auto message = std::move(*shared_message);
                        bool is_closed = self->IsStreamClosed();
                        bool is_clean = self->IsStreamClosedCleanly();
                        bool fail_open = self->IsFailOpenAllowed();
                        GRPC_TRACE_LOG(ext_proc_filter, INFO)
                            << "ExtProc: S2C bypass check: is_closed="
                            << is_closed << ", is_clean=" << is_clean
                            << ", fail_open=" << fail_open;
                        if (self->config()
                                ->processing_mode->send_response_body &&
                            is_closed) {
                          if (!is_clean && !fail_open) {
                            GRPC_TRACE_LOG(ext_proc_filter, INFO)
                                << "ExtProc: S2C bypass check failing closed "
                                   "with status: "
                                << self->GetStreamStatus();
                            return self->GetStreamStatus();
                          }
                        }
                        GRPC_TRACE_LOG(ext_proc_filter, INFO)
                            << "ExtProc: ServerToClient S2C Write Loop "
                               "bypassing ext_proc";
                        self->handler_.SpawnPushMessage(std::move(message));
                        return absl::OkStatus();
                      });
                });
          }),
      // Mark server writes done when polling finishes.
      [self = WeakRefAsSubclass<ExtProcCall>()]() {
        self->SetServerToClientWritesDone();
        return absl::OkStatus();
      });
}

absl::AnyInvocable<Poll<absl::Status>()>
ExtProcFilter::ExtProcCall::ReadServerToClientMessagesFromExtProcServer() {
  GRPC_TRACE_LOG(ext_proc_filter, INFO)
      << "ExtProc: ReadServerToClientMessagesFromExtProcServer started";
  // Read from response_body_pipe_, construct message, push to
  // handler.
  return ForEach(
      std::move(response_body_pipe().receiver),
      [self = WeakRefAsSubclass<ExtProcCall>()](
          absl::StatusOr<ExtProcResponse> response) mutable {
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
        auto new_msg = self->handler_.arena()->MakePooled<Message>(
            SliceBuffer(std::move(slice)), /*flags=*/0);
        GRPC_TRACE_LOG(ext_proc_filter, INFO)
            << "ExtProcCall " << self.get()
            << ": Pushing message downstream (normal mode)";
        self->handler_.SpawnPushMessage(std::move(new_msg));
        return absl::OkStatus();
      });
}

absl::AnyInvocable<Poll<absl::Status>()>
ExtProcFilter::ExtProcCall::ServerToClientMessagesNormalMode() {
  GRPC_TRACE_LOG(ext_proc_filter, INFO)
      << "ExtProc: ServerToClientMessagesNormalMode started";
  return Map(
      TryJoin<absl::StatusOr>(SendServerToClientMessagesToExtProcServer(),
                              ReadServerToClientMessagesFromExtProcServer()),
      [](auto result) -> absl::Status { return result.status(); });
}

absl::AnyInvocable<Poll<absl::Status>()>
ExtProcFilter::ExtProcCall::ServerToClientMessages() {
  const bool send_body =
      config()->processing_mode->send_response_body && !IsStreamClosed();
  if (!send_body) {
    GRPC_TRACE_LOG(ext_proc_filter, INFO)
        << "ExtProc: ServerToClientMessagesNonProcessingMode started";
    return ForEach(MessagesFrom(initiator_),
                   [self = WeakRefAsSubclass<ExtProcCall>()](
                       MessageHandle message) mutable {
                     GRPC_TRACE_LOG(ext_proc_filter, INFO)
                         << "ExtProc: "
                            "ServerToClientMessagesNonProcessingMode "
                            "forwarding message";
                     self->handler_.SpawnPushMessage(std::move(message));
                     return absl::OkStatus();
                   });
  } else if (config()->observability_mode) {
    return ServerToClientMessagesObservabilityMode();
  } else {
    return ServerToClientMessagesNormalMode();
  }
}

absl::AnyInvocable<Poll<absl::Status>()>
ExtProcFilter::ExtProcCall::ReadServerTrailingMetadataFromExtProcServer(
    std::shared_ptr<ServerMetadataHandle> metadata, Timestamp start_time) {
  auto config = this->config();
  GRPC_TRACE_LOG(ext_proc_filter, INFO)
      << "ExtProc: ReadServerTrailingMetadataFromExtProcServer started";
  return Map(
      // Wait on response_trailers_latch, which is set when the external
      // processor returns the response to our ServerTrailingMetadata
      // request (or when the stream terminates/fails).
      response_trailers_latch().Wait(),
      [self = WeakRefAsSubclass<ExtProcCall>(), metadata = std::move(metadata),
       config = std::move(config), start_time](
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
                                       self->server_trailers_sent())) {
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
            self->ext_proc_filter_->RecordServerTrailersDuration(
                (Timestamp::Now() - start_time).seconds());
            self->handler_.SpawnPushServerTrailingMetadata(
                std::move(*metadata));
            self->initiator_.SpawnCancel();
            self->CloseStream();
            return absl::OkStatus();
          }
          // When trailing metadata is received, no further body responses are
          // expected from the external processor. If body processing was
          // enabled in normal mode and the pipe sender is not yet closed,
          // explicitly close it to cleanly terminate any asynchronous body
          // read loops.
          if (!config->observability_mode) {
            if (!self->response_body_pipe().sender.IsClosed()) {
              self->response_body_pipe().sender.MarkClosed();
            }
            if (!self->request_body_pipe().sender.IsClosed()) {
              self->request_body_pipe().sender.MarkClosed();
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
        self->ext_proc_filter_->RecordServerTrailersDuration(
            (Timestamp::Now() - start_time).seconds());
        self->handler_.SpawnPushServerTrailingMetadata(std::move(*metadata));
        return absl::OkStatus();
      });
}

absl::AnyInvocable<Poll<absl::Status>()>
ExtProcFilter::ExtProcCall::ServerTrailingMetadataNormalMode(
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
      drain_requested(),
      [self = WeakRefAsSubclass<ExtProcCall>(), metadata]() mutable {
        GRPC_TRACE_LOG(ext_proc_filter, INFO)
            << "ExtProc: Drain active before sending Server Trailing Metadata, "
               "blocking propagation";
        return Map(self->WaitForStreamStatus(),
                   [self, metadata = std::move(metadata)](
                       absl::Status status) mutable -> absl::Status {
                     GRPC_TRACE_LOG(ext_proc_filter, INFO)
                         << "ExtProc: Server Trailing Metadata Drain complete "
                            "(pre-existing). Status: "
                         << status;
                     if (!self->IsStreamClosedCleanly() &&
                         !self->IsFailOpenAllowed()) {
                       return status;
                     }
                     self->handler_.SpawnPushServerTrailingMetadata(
                         std::move(*metadata));
                     return absl::OkStatus();
                   });
      },
      [self = WeakRefAsSubclass<ExtProcCall>(), metadata,
       start_time]() mutable {
        return Seq(
            self->SendServerTrailingMetadataRequest(metadata),
            [self, metadata, start_time](absl::Status status) mutable
                -> absl::AnyInvocable<Poll<absl::Status>()> {
              if (!status.ok()) {
                if (self->IsFailOpenAllowed()) {
                  GRPC_TRACE_LOG(ext_proc_filter, INFO)
                      << "ExtProc: Server trailing metadata send failed, but "
                         "fail-open is allowed. Error: "
                      << status;
                  self->handler_.SpawnPushServerTrailingMetadata(
                      std::move(*metadata));
                  return
                      []() -> Poll<absl::Status> { return absl::OkStatus(); };
                }
                absl::Status err =
                    self->IsStreamClosed() ? self->GetStreamStatus() : status;
                return [err]() -> Poll<absl::Status> { return err; };
              }
              return self->ReadServerTrailingMetadataFromExtProcServer(
                  std::move(metadata), start_time);
            });
      });
}

absl::AnyInvocable<Poll<absl::Status>()>
ExtProcFilter::ExtProcCall::ServerTrailingMetadataObservabilityMode(
    std::shared_ptr<ServerMetadataHandle> metadata) {
  GRPC_TRACE_LOG(ext_proc_filter, INFO)
      << "ExtProc: ServerTrailingMetadataObservabilityMode pulled. metadata: "
      << (*metadata)->DebugString();
  Timestamp start_time = Timestamp::Now();
  // Asynchronously send the ServerTrailers message to the external processor
  // provided the ext_proc stream is still open. In observability mode, traffic
  // is strictly observed and not modified.
  return Seq(
      SendServerTrailingMetadataRequest(metadata),
      [self = WeakRefAsSubclass<ExtProcCall>(), metadata,
       start_time](absl::Status status) mutable {
        // Ensure the response body pipe sender is marked closed when trailing
        // metadata arrives, cleanly terminating any ongoing asynchronous read
        // loops.
        if (self->config()->processing_mode->send_response_body &&
            !self->config()->observability_mode &&
            !self->response_body_pipe().sender.IsClosed()) {
          self->response_body_pipe().sender.MarkClosed();
        }
        // If sending the message failed or the ext_proc stream closed with an
        // error (e.g., disconnection or RESOURCE_EXHAUSTED), check failure mode
        // configuration. Unless failure_mode_allow is enabled (which allows
        // proceeding despite observability failures), replace the trailing
        // metadata with a cancelled status corresponding to the error.
        if ((!status.ok() || self->IsStreamClosed()) &&
            !self->IsFailOpenAllowed()) {
          if (self->IsStreamClosedCleanly()) {
            GRPC_TRACE_LOG(ext_proc_filter, INFO)
                << "ExtProc: Ignored server trailing metadata send failure "
                   "in observability mode due to clean close: "
                << status;
          } else {
            absl::Status error_status = status;
            if (self->IsStreamClosed() && !self->GetStreamStatus().ok()) {
              error_status = self->GetStreamStatus();
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
        self->ext_proc_filter_->RecordServerTrailersDuration(
            (Timestamp::Now() - start_time).seconds());
        self->handler_.SpawnPushServerTrailingMetadata(std::move(*metadata));
        return absl::OkStatus();
      });
}

absl::AnyInvocable<Poll<absl::Status>()>
ExtProcFilter::ExtProcCall::ServerTrailingMetadataNonProcessingMode(
    std::shared_ptr<ServerMetadataHandle> metadata) {
  GRPC_TRACE_LOG(ext_proc_filter, INFO)
      << "ExtProc: ServerTrailingMetadataNonProcessingMode pulled. metadata: "
      << (*metadata)->DebugString();
  // Even when trailing metadata is not sent to ext_proc, its arrival signals
  // that no further response bodies will be sent. If body processing was
  // enabled, explicitly close the pipe sender to cleanly terminate any
  // asynchronous body read loops.
  if (config()->processing_mode->send_response_body &&
      !config()->observability_mode &&
      !response_body_pipe().sender.IsClosed()) {
    response_body_pipe().sender.MarkClosed();
  }
  GRPC_TRACE_LOG(ext_proc_filter, INFO)
      << "ExtProc: ServerTrailingMetadata pushing metadata immediately";
  // Immediately push the unmutated server trailing metadata downstream.
  handler_.SpawnPushServerTrailingMetadata(std::move(*metadata));
  return []() -> Poll<absl::Status> { return absl::OkStatus(); };
}

// Helper that checks if the external processor stream is already closed or
// half-closed.
// If it closed with an error and the configuration does NOT allow fail-open
// (server_fail_open_allowed=false), returns a promise resolving to that error.
// If it closed cleanly, or closed with error but fail-open IS allowed,
// falls back to pushing the unmutated trailing metadata downstream immediately.
// Returns std::nullopt if the stream is active and processing should continue.
absl::optional<absl::AnyInvocable<Poll<absl::Status>()>>
ExtProcFilter::ExtProcCall::MaybeHandleClosedStream(
    std::shared_ptr<ServerMetadataHandle> metadata) {
  if (IsStreamClosed() || ext_proc_stream_half_closed()) {
    absl::Status error = GetStreamStatus();
    if (!error.ok() && !IsFailOpenAllowed()) {
      return [error]() -> Poll<absl::Status> { return error; };
    }
    return ServerTrailingMetadataNonProcessingMode(std::move(metadata));
  }
  return std::nullopt;
}

// Orchestrates the server trailing metadata step when the RPC is
// "trailers-only". (i.e. backend immediately sent trailing metadata without any
// preceding body or initial metadata).
absl::AnyInvocable<Poll<absl::Status>()>
ExtProcFilter::ExtProcCall::ServerTrailingMetadataTrailersOnly(
    std::shared_ptr<ServerMetadataHandle> metadata) {
  // If the ext_proc stream has closed prematurely, route immediately to
  // error propagation or unmutated fallback.
  if (auto promise = MaybeHandleClosedStream(metadata); promise.has_value()) {
    return std::move(*promise);
  }
  // Determine if we should attempt to send trailers-only headers to the
  // processor, which requires the config setting and an active ext_proc stream.
  const bool send_headers = config()->processing_mode->send_response_headers &&
                            !IsStreamClosed() && !ext_proc_stream_half_closed();
  // Route to the appropriate handler based on configuration.
  if (!send_headers) {
    return ServerTrailingMetadataNonProcessingMode(std::move(metadata));
  } else if (config()->observability_mode) {
    return ServerInitialMetadataObservabilityMode(std::move(metadata));
  } else {
    return ServerTrailingMetadataTrailersOnlyNormalMode(std::move(metadata));
  }
}

// Orchestrates the server trailing metadata step for a normal RPC (one that has
// sent initial metadata and/or response body before finishing).
absl::AnyInvocable<Poll<absl::Status>()>
ExtProcFilter::ExtProcCall::ServerTrailingMetadataNormal(
    std::shared_ptr<ServerMetadataHandle> metadata) {
  // If the ext_proc stream has closed prematurely, route immediately to
  // error propagation or unmutated fallback.
  if (auto promise = MaybeHandleClosedStream(metadata); promise.has_value()) {
    return std::move(*promise);
  }
  // Determine if we should attempt to send trailers to the processor.
  // Trailers are only sent if processing is enabled in config, the backend
  // returned an OK status (errors skip trailing metadata processing), and the
  // ext_proc stream is active.
  const bool send_trailers =
      config()->processing_mode->send_response_trailers &&
      IsStatusOk(*metadata) && !IsStreamClosed() &&
      !ext_proc_stream_half_closed();
  if (!send_trailers) {
    return ServerTrailingMetadataNonProcessingMode(std::move(metadata));
  } else if (config()->observability_mode) {
    return ServerTrailingMetadataObservabilityMode(std::move(metadata));
  } else {
    return ServerTrailingMetadataNormalMode(std::move(metadata));
  }
}

// Main dispatcher function for the ServerTrailingMetadata filter interceptor
// step. Distinguishes between "trailers-only" RPCs and normal RPCs and routes
// accordingly.
absl::AnyInvocable<Poll<absl::Status>()>
ExtProcFilter::ExtProcCall::ServerTrailingMetadata(
    std::shared_ptr<ServerMetadataHandle> metadata) {
  // Check if this response is "trailers-only" (i.e. backend ended the RPC
  // immediately without sending response headers first).
  const bool is_trailers_only =
      (*metadata)->get(GrpcTrailersOnly()).value_or(false);
  if (is_trailers_only) {
    SetIsTrailersOnly();
  }
  // Dispatch to the appropriate handler based on whether the response is
  // trailers-only.
  if (is_trailers_only) {
    return ServerTrailingMetadataTrailersOnly(std::move(metadata));
  }
  return ServerTrailingMetadataNormal(std::move(metadata));
}

// Intercepts and processes client-to-server messages.
// Forwards client messages to backend without processing when request body
// processing is disabled or ext_proc stream is closed.
absl::AnyInvocable<Poll<absl::Status>()>
ExtProcFilter::ExtProcCall::ClientToServerMessagesNonProcessingMode() {
  GRPC_TRACE_LOG(ext_proc_filter, INFO)
      << "ExtProc: ClientToServerMessagesNonProcessingMode started";
  return Seq(
      ForEach(MessagesFrom(handler_),
              [self = WeakRefAsSubclass<ExtProcCall>()](
                  MessageHandle message) mutable {
                GRPC_TRACE_LOG(ext_proc_filter, INFO)
                    << "ExtProc: ClientToServerMessagesNonProcessingMode got "
                       "message";
                return If(
                    self->ext_proc_set_eos(),
                    []() -> absl::Status {
                      return absl::InternalError(
                          "Client sends closed by external processor");
                    },
                    [self, message = std::move(message)]() mutable {
                      self->initiator_.SpawnPushMessage(std::move(message));
                      return absl::OkStatus();
                    });
              }),
      [self = WeakRefAsSubclass<ExtProcCall>()]() mutable {
        GRPC_TRACE_LOG(ext_proc_filter, INFO)
            << "ExtProc: ClientToServerMessagesNonProcessingMode finished "
               "sends";
        self->initiator_.SpawnFinishSends();
        return absl::OkStatus();
      });
}

// Handles client-to-server messages in observability mode
absl::AnyInvocable<Poll<absl::Status>()>
ExtProcFilter::ExtProcCall::ClientToServerMessagesObservabilityMode(
    ::google_protobuf_Struct* attributes) {
  GRPC_TRACE_LOG(ext_proc_filter, INFO)
      << "ExtProc: ClientToServerMessagesObservabilityMode started";
  return TrySeq(
      ForEach(
          MessagesFrom(handler_),
          [self = WeakRefAsSubclass<ExtProcCall>(),
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
                self->ext_proc_set_eos(),
                []() -> absl::Status {
                  return absl::InternalError(
                      "Client sends closed by external processor");
                },
                [self, attributes, message = std::move(message)]() mutable {
                  return Map(
                      If(
                          !self->IsStreamClosed(),
                          [self, &message, attributes]() {
                            return self->SendClientMessageRequest(
                                message,
                                /*end_of_stream=*/false,
                                /*end_of_stream_without_message=*/false,
                                attributes);
                          },
                          []() -> absl::Status { return absl::OkStatus(); }),
                      [self, message = std::move(message)](
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
                            !self->config()->failure_mode_allow) {
                          if (self->IsStreamClosedCleanly()) {
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
                        self->initiator_.SpawnPushMessage(std::move(message));
                        return absl::OkStatus();
                      });
                });
          }),
      // After client finishes sending all messages (WritesDone).
      [self = WeakRefAsSubclass<ExtProcCall>(), attributes]() mutable {
        GRPC_TRACE_LOG(ext_proc_filter, INFO)
            << "ExtProc: ClientToServerMessagesObservabilityMode finished "
               "sends";
        Timestamp start_time = Timestamp::Now();
        return Map(
            If(
                !self->IsStreamClosed(),
                [self, attributes]() {
                  MessageHandle null_msg = nullptr;
                  return self->SendClientMessageRequest(
                      null_msg,
                      /*end_of_stream=*/false,
                      /*end_of_stream_without_message=*/true, attributes);
                },
                []() -> absl::Status { return absl::OkStatus(); }),
            [self, start_time](absl::Status status) mutable -> absl::Status {
              if (!status.ok()) {
                GRPC_TRACE_LOG(ext_proc_filter, INFO)
                    << "ExtProc: Failed to send client half-close in "
                       "observability mode: "
                    << status;
              }
              self->ext_proc_filter_->RecordClientHalfCloseDuration(
                  (Timestamp::Now() - start_time).seconds());
              self->initiator_.SpawnFinishSends();
              return absl::OkStatus();
            });
      });
}

absl::AnyInvocable<Poll<absl::Status>()>
ExtProcFilter::ExtProcCall::ClientToSidestreamNormalMode(
    ::google_protobuf_Struct* attributes) {
  return TrySeq(
      ForEach(
          MessagesFrom(handler_),
          [self = WeakRefAsSubclass<ExtProcCall>(),
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
                self->drain_requested(),
                [self, shared_message]() mutable {
                  GRPC_TRACE_LOG(ext_proc_filter, INFO)
                      << "ExtProc: Drain active, blocking data plane read";
                  return Map(self->WaitForStreamStatus(),
                             [self, shared_message](
                                 absl::Status status) mutable -> absl::Status {
                               GRPC_TRACE_LOG(ext_proc_filter, INFO)
                                   << "ExtProc: Drain complete (stream "
                                      "closed), resuming data plane. Status: "
                                   << status;
                               // If stream did not close cleanly and fail-open
                               // is not allowed, return error status.
                               if (!self->IsStreamClosedCleanly() &&
                                   !self->IsFailOpenAllowed()) {
                                 return self->GetStreamStatus();
                               }
                               // Otherwise, resume data plane bypass and
                               // push message.
                               if (*shared_message != nullptr) {
                                 self->initiator_.SpawnPushMessage(
                                     std::move(*shared_message));
                               }
                               return absl::OkStatus();
                             });
                },
                [self, attributes, shared_message]() mutable {
                  return If(
                      self->ext_proc_set_eos(),
                      []() {
                        // TODO(rishesh): Once PH2 work is done, we should make
                        // this pass (discard or handle cleanly). Currently we
                        // fail the RPC to avoid crashes on half-closed
                        // transport.
                        return absl::InternalError(
                            "Client sends closed by external processor");
                      },
                      [self, attributes, shared_message]() mutable {
                        const bool send_message =
                            !self->IsStreamClosed() &&
                            !self->ext_proc_stream_half_closed();
                        return Map(
                            If(
                                send_message,
                                [self, shared_message, attributes]() {
                                  return self->SendClientMessageRequest(
                                      *shared_message,
                                      /*end_of_stream=*/false,
                                      /*end_of_stream_without_message=*/
                                      false, attributes);
                                },
                                []() -> absl::Status {
                                  return absl::OkStatus();
                                }),
                            [self, send_message, shared_message](
                                absl::Status status) mutable -> absl::Status {
                              if (!send_message) {
                                // Stream closed before we could send. If not
                                // cleanly closed and fail-open is not allowed,
                                // return error status immediately.
                                if (!self->IsStreamClosedCleanly() &&
                                    !self->IsFailOpenAllowed()) {
                                  return self->IsStreamClosed()
                                             ? self->GetStreamStatus()
                                             : status;
                                }
                                // Otherwise, bypass ext_proc and push message.
                                if (*shared_message != nullptr) {
                                  self->initiator_.SpawnPushMessage(
                                      std::move(*shared_message));
                                }
                                return absl::OkStatus();
                              }
                              // Message was sent, wait for response in
                              // sidestream_to_server loop.
                              if (!status.ok() || self->IsStreamClosed()) {
                                // If not cleanly closed and fail-open is not
                                // allowed, return error status immediately.
                                if (!self->IsStreamClosedCleanly() &&
                                    !self->IsFailOpenAllowed()) {
                                  return self->IsStreamClosed()
                                             ? self->GetStreamStatus()
                                             : status;
                                }
                                // Otherwise, bypass ext_proc and push message.
                                if (*shared_message != nullptr) {
                                  self->initiator_.SpawnPushMessage(
                                      std::move(*shared_message));
                                }
                              }
                              return absl::OkStatus();
                            });
                      });
                });
          }),
      [self = WeakRefAsSubclass<ExtProcCall>(), attributes]() mutable {
        // This promise runs when the client has finished sending all messages
        // (WritesDone). We must transition the client-to-server direction to
        // half-closed.
        return If(
            self->ext_proc_set_eos(),
            // If the external processor already closed the stream (EOS),
            // we don't need to notify it. Just mark client sends as done.
            [self]() {
              self->SetClientSendsDone();
              return absl::OkStatus();
            },
            [self, attributes]() mutable {
              // Prepare an empty message with
              // end_of_stream_without_message=true to signal half-close to the
              // external processor.
              MessageHandle null_msg = nullptr;
              const bool send_message = !self->IsStreamClosed() &&
                                        !self->ext_proc_stream_half_closed();
              return Map(
                  If(
                      send_message,
                      [self, attributes]() {
                        MessageHandle null_msg = nullptr;
                        return self->SendClientMessageRequest(
                            null_msg,
                            /*end_of_stream=*/false,
                            /*end_of_stream_without_message=*/true, attributes);
                      },
                      []() -> absl::Status { return absl::OkStatus(); }),
                  [self,
                   send_message](absl::Status status) mutable -> absl::Status {
                    // If we did not attempt to send the half-close (because the
                    // stream was already closed), or if the send failed/stream
                    // closed during send: we must decide whether to fail the
                    // call or bypass the error.
                    if (!send_message) {
                      if (self->drain_requested() ||
                          self->IsStreamClosedCleanly() ||
                          self->IsFailOpenAllowed()) {
                        // Bypass error: signal half-close to backend
                        // immediately since we won't get a response from
                        // ext_proc.
                        self->initiator_.SpawnFinishSends();
                        self->SetClientSendsDone();
                        return absl::OkStatus();
                      } else {
                        // Fail-closed: propagate the stream error.
                        return self->IsStreamClosed() ? self->GetStreamStatus()
                                                      : status;
                      }
                    }
                    if (!status.ok() || self->IsStreamClosed()) {
                      if (self->IsStreamClosedCleanly() ||
                          self->IsFailOpenAllowed()) {
                        // Bypass error: signal half-close to backend
                        // immediately.
                        self->initiator_.SpawnFinishSends();
                        self->SetClientSendsDone();
                        return absl::OkStatus();
                      } else {
                        // Fail-closed: propagate the stream error.
                        return self->IsStreamClosed() ? self->GetStreamStatus()
                                                      : status;
                      }
                    }
                    // Success: The half-close request was sent to ext_proc.
                    // We do NOT call initiator.SpawnFinishSends() here because
                    // we must wait for the ext_proc server to respond and close
                    // the receiver pipe. The `sidestream_to_server` promise
                    // will handle calling SpawnFinishSends() when that happens.
                    self->SetClientSendsDone();
                    return absl::OkStatus();
                  });
            });
      });
}

// Handles processing responses from the external processing server (sidestream)
// and forwarding the (possibly mutated) request body to the backend server.
absl::AnyInvocable<Poll<absl::Status>()>
ExtProcFilter::ExtProcCall::SidestreamToServerNormalMode() {
  return Seq(
      ForEach(std::move(request_body_pipe().receiver),
              [self = WeakRefAsSubclass<ExtProcCall>()](
                  absl::StatusOr<ExtProcResponse> result) mutable {
                GRPC_TRACE_LOG(ext_proc_filter, INFO)
                    << "ExtProc: sidestream_to_server ForEach got item, ok: "
                    << result.ok();
                if (!result.ok()) {
                  // If the stream failed but fail-open is allowed, we ignore
                  // the error and proceed. Otherwise, we propagate the error.
                  if (self->IsFailOpenAllowed()) {
                    return absl::OkStatus();
                  }
                  return result.status();
                }
                if (const auto* request_body =
                        std::get_if<ExtProcResponse::RequestBody>(
                            &result->response)) {
                  if (!request_body->mutation.end_of_stream_without_message) {
                    GRPC_TRACE_LOG(ext_proc_filter, INFO)
                        << "ExtProc: ClientToServerMessages playing body "
                           "mutation: "
                        << request_body->mutation.body.size() << "b";
                    auto slice =
                        Slice::FromCopiedString(request_body->mutation.body);
                    auto new_msg =
                        self->initiator_.arena()->MakePooled<Message>(
                            SliceBuffer(std::move(slice)), /*flags=*/0);
                    self->initiator_.SpawnPushMessage(std::move(new_msg));
                  }
                }
                return absl::OkStatus();
              }),
      // This lambda runs after the ForEach loop finishes (either due to EOF or
      // error).
      [self = WeakRefAsSubclass<ExtProcCall>()](absl::Status status) mutable {
        Timestamp start_time = Timestamp::Now();
        GRPC_TRACE_LOG(ext_proc_filter, INFO)
            << "ExtProc: ClientToServerMessages finished sends, status: "
            << status.ToString()
            << ", c2s_write_done: " << self->c2s_write_done()
            << ", IsStreamClosed: " << self->IsStreamClosed();
        // If we have finished sending all client messages to the ext_proc
        // server, or if the ext_proc stream was closed (e.g. due to immediate
        // response), we signal the backend server that we are done sending the
        // request body.
        if (self->c2s_write_done() || !self->IsStreamClosed()) {
          GRPC_TRACE_LOG(ext_proc_filter, INFO)
              << "ExtProc: Calling SpawnFinishSends";
          self->ext_proc_filter_->RecordClientHalfCloseDuration(
              (Timestamp::Now() - start_time).seconds());
          self->initiator_.SpawnFinishSends();
        }
        return status;
      });
}

absl::AnyInvocable<Poll<absl::Status>()>
ExtProcFilter::ExtProcCall::ClientToServerMessagesNormalMode(
    ::google_protobuf_Struct* attributes) {
  return Map(
      TryJoin<absl::StatusOr>(ClientToSidestreamNormalMode(attributes),
                              SidestreamToServerNormalMode()),
      [self = WeakRefAsSubclass<ExtProcCall>()](auto result) -> absl::Status {
        GRPC_TRACE_LOG(ext_proc_filter, INFO)
            << "ClientToServerMessagesNormalMode result: " << result.status()
            << ", fail_open_allowed: " << self->IsFailOpenAllowed()
            << ", stream_error: " << self->GetStreamStatus();
        if (!result.ok()) {
          return result.status();
        }
        if (self->IsFailOpenAllowed()) {
          return absl::OkStatus();
        }
        return self->GetStreamStatus();
      });
}

absl::AnyInvocable<Poll<absl::Status>()>
ExtProcFilter::ExtProcCall::ClientToServerMessages(
    ::google_protobuf_Struct* attributes) {
  const bool send_request_body =
      config()->processing_mode->send_request_body && !IsStreamClosed();
  if (!send_request_body) {
    return ClientToServerMessagesNonProcessingMode();
  } else if (config()->observability_mode) {
    return ClientToServerMessagesObservabilityMode(attributes);
  } else {
    return ClientToServerMessagesNormalMode(attributes);
  }
}

absl::AnyInvocable<Poll<absl::Status>()>
ExtProcFilter::ExtProcCall::ClientToServerObservabilityMode() {
  Timestamp start_time = Timestamp::Now();
  return TrySeq(
      handler_.PullClientInitialMetadata(),
      [self = Ref(), start_time](ClientMetadataHandle metadata) mutable
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
            self->SendClientInitialMetadataRequest(
                shared_metadata,
                self->ext_proc_filter_->default_authority_.as_string_view()),
            [failure_mode_allow =
                 self->ext_proc_filter_->config_->failure_mode_allow.value_or(
                     false),
             self](absl::Status status) -> absl::Status {
              if (!status.ok()) {
                if (failure_mode_allow) {
                  GRPC_TRACE_LOG(ext_proc_filter, INFO)
                      << "ExtProc: Initial metadata write failed, but "
                         "failure_mode_allow=true. Proceeding with fail-open "
                         "behavior. Error: "
                      << status;
                  return absl::OkStatus();
                }
                if (self->IsStreamClosed() && !self->GetStreamStatus().ok()) {
                  return self->GetStreamStatus();
                }
              }
              return status;
            });
        // After the write attempt (successful or failed-open), we immediately
        // start the child call to the backend server. We do NOT wait for
        // responses from ext_proc.
        return TrySeq(
            std::move(write_promise),
            [self, shared_metadata = std::move(shared_metadata),
             start_time]() mutable -> absl::AnyInvocable<Poll<absl::Status>()> {
              self->ext_proc_filter_->RecordClientHeadersDuration(
                  (Timestamp::Now() - start_time).seconds());
              self->initiator_ = self->ext_proc_filter_->MakeChildCall(
                  std::move(*shared_metadata), self->handler_.arena()->Ref());
              self->handler_.AddChildCall(self->initiator_);
              // Spawn background task to handle server-to-client path
              // (responses).
              self->initiator_.SpawnInfallible(
                  "server_to_client", [self]() mutable {
                    GRPC_TRACE_LOG(ext_proc_filter, INFO)
                        << "ExtProc: server_to_client task started";
                    return self->initiator_.CancelIfFails(
                        self->ServerToClientCall());
                  });
              // Continue with forwarding client messages (request body).
              return self->ClientToServerMessages(/*attributes=*/nullptr);
            });
      });
}

absl::AnyInvocable<Poll<absl::Status>()>
ExtProcFilter::ExtProcCall::ClientToServerCallNormalMode() {
  Timestamp start_time = Timestamp::Now();
  return TrySeq(
      handler_.PullClientInitialMetadata(),
      [self = Ref()](ClientMetadataHandle metadata) mutable {
        GRPC_TRACE_LOG(ext_proc_filter, INFO)
            << "ExtProc: Client initial metadata received:\n"
            << metadata->DebugString();
        auto shared_metadata =
            std::make_shared<ClientMetadataHandle>(std::move(metadata));
        return Seq(
            self->SendClientInitialMetadataRequest(
                shared_metadata,
                self->ext_proc_filter_->default_authority_.as_string_view()),
            [self, shared_metadata](absl::Status status) mutable
                -> absl::StatusOr<ClientMetadataHandle> {
              if (!status.ok()) {
                if (self->IsFailOpenAllowed()) {
                  GRPC_TRACE_LOG(ext_proc_filter, INFO)
                      << "ExtProc: Client initial metadata send failed, but "
                         "fail-open is allowed. Error: "
                      << status;
                  return std::move(*shared_metadata);
                }
                return (self->IsStreamClosed() && !self->GetStreamStatus().ok())
                           ? self->GetStreamStatus()
                           : status;
              }
              return std::move(*shared_metadata);
            });
      },
      [self = Ref(), start_time](ClientMetadataHandle metadata) mutable {
        return TrySeq(
            self->request_headers_latch().Wait(),
            // Process the response from ext_proc.
            [self,
             metadata = std::move(metadata)](ExtProcResponse response) mutable
                -> absl::StatusOr<ClientMetadataHandle> {
              // Apply header mutations if returned by ext_proc.
              if (const auto* headers =
                      std::get_if<ExtProcResponse::RequestHeaders>(
                          &response.response);
                  headers != nullptr) {
                const auto* rules =
                    self->ext_proc_filter_->config_->mutation_rules.has_value()
                        ? &self->ext_proc_filter_->config_->mutation_rules
                               .value()
                        : nullptr;
                auto status =
                    ApplyHeaderMutations(headers->mutation, rules, *metadata);
                if (!status.ok()) return status;
              }
              return std::move(metadata);
            },
            // Handle the result of response processing.
            [self, start_time](ClientMetadataHandle metadata) mutable
                -> absl::AnyInvocable<Poll<absl::Status>()> {
              self->ext_proc_filter_->RecordClientHeadersDuration(
                  (Timestamp::Now() - start_time).seconds());
              self->initiator_ = self->ext_proc_filter_->MakeChildCall(
                  std::move(metadata), self->handler_.arena()->Ref());
              self->handler_.AddChildCall(self->initiator_);
              // Spawn background task to handle server-to-client path.
              self->initiator_.SpawnInfallible(
                  "server_to_client", [self]() mutable {
                    GRPC_TRACE_LOG(ext_proc_filter, INFO)
                        << "ExtProc: server_to_client task started";
                    return self->initiator_.CancelIfFails(
                        self->ServerToClientCall());
                  });
              return self->ClientToServerMessages(/*attributes=*/nullptr);
            });
      });
}

absl::AnyInvocable<Poll<absl::Status>()>
ExtProcFilter::ExtProcCall::ClientToServerCallNonProcessingMode() {
  return TrySeq(
      handler_.PullClientInitialMetadata(),
      [self = Ref()](ClientMetadataHandle metadata) mutable
          -> absl::AnyInvocable<Poll<absl::Status>()> {
        GRPC_TRACE_LOG(ext_proc_filter, INFO)
            << "ExtProc: Client initial metadata received (non-processing):\n"
            << metadata->DebugString();
        const auto& processing_mode =
            *self->ext_proc_filter_->config_->processing_mode;
        ::google_protobuf_Struct* attributes = nullptr;
        if (processing_mode.send_request_body &&
            !self->ext_proc_filter_->config_->request_attributes.empty()) {
          auto* arena = self->handler_.arena()->New<upb::Arena>();
          attributes = CreateExtProcAttributesProtoStruct(
              arena->ptr(), self->ext_proc_filter_->config_->request_attributes,
              *metadata,
              self->ext_proc_filter_->default_authority_.as_string_view());
        }
        self->initiator_ = self->ext_proc_filter_->MakeChildCall(
            std::move(metadata), self->handler_.arena()->Ref());
        self->handler_.AddChildCall(self->initiator_);
        // Spawn background task to handle server-to-client path.
        self->initiator_.SpawnInfallible("server_to_client", [self]() mutable {
          GRPC_TRACE_LOG(ext_proc_filter, INFO)
              << "ExtProc: server_to_client task started";
          return self->initiator_.CancelIfFails(self->ServerToClientCall());
        });
        return self->ClientToServerMessages(attributes);
      });
}

// Handles the response path (Server to Client).
// This function sets up a pipeline to process server initial metadata,
// response messages, and server trailing metadata, potentially intercepting
// and mutating them via the ext_proc server.
//
// It also watches for ext_proc stream errors and aborts the call if a failure
// occurs and fail-open is not allowed.
absl::AnyInvocable<Poll<absl::Status>()>
ExtProcFilter::ExtProcCall::ServerToClientCall() {
  GRPC_TRACE_LOG(ext_proc_filter, INFO)
      << "ExtProcCall " << this << " ServerToClientCall started";
  // Pipeline for normal response processing.
  auto response_pipeline = Seq(
      // Phase 1: Process initial metadata and response messages.
      TrySeq(
          // Step A: Pull Server Initial Metadata from the backend server.
          initiator_.PullServerInitialMetadata(),
          [self = Ref()](std::optional<ServerMetadataHandle> md) mutable {
            const bool has_md = md.has_value();
            return If(
                has_md,
                [self, md = std::move(md)]() mutable {
                  auto shared_md =
                      std::make_shared<ServerMetadataHandle>(std::move(*md));
                  return TrySeq(
                      // Step 1: Intercept, send to ext_proc, and apply
                      // mutations to Server Initial Metadata.
                      self->ServerInitialMetadata(shared_md),
                      // Step 2: Intercept and process Server-to-Client Messages
                      // (body).
                      [self]() mutable {
                        return self->ServerToClientMessages();
                      });
                },
                []() {
                  // Trailers-Only response: Bypasses both headers and messages!
                  return absl::OkStatus();
                });
          }),
      // Phase 2: Process trailing metadata.
      // This runs after Phase 1 (headers and messages) is complete.
      [self = Ref()](absl::Status status) mutable {
        if (!status.ok()) {
          // If Phase 1 failed, we propagate the error.
          return absl::AnyInvocable<Poll<absl::Status>()>(
              [status]() -> Poll<absl::Status> { return status; });
        }
        // Phase 1 succeeded. Pull and process trailing metadata.
        return absl::AnyInvocable<Poll<absl::Status>()>(
            Seq(self->initiator_.PullServerTrailingMetadata(),
                [self](ServerMetadataHandle md) mutable {
                  auto shared_md =
                      std::make_shared<ServerMetadataHandle>(std::move(md));
                  // Intercept, send to ext_proc, and apply mutations to
                  // Trailing Metadata.
                  return self->ServerTrailingMetadata(shared_md);
                }));
      });
  // Monitor the ext_proc stream for errors.
  // If the ext_proc stream fails and fail-open is NOT allowed, we abort the
  // call.
  auto watch_error = Seq(
      WaitForStreamStatus(),
      [self = Ref()](
          absl::Status status) -> absl::AnyInvocable<Poll<absl::Status>()> {
        GRPC_TRACE_LOG(ext_proc_filter, INFO)
            << "watch_error stream_status: " << status
            << ", failure_mode_allow: "
            << (self->config()->failure_mode_allow.has_value()
                    ? (*self->config()->failure_mode_allow ? "true" : "false")
                    : "unset");
        if (!status.ok() &&
            !self->config()->failure_mode_allow.value_or(false)) {
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
  return [self = Ref(),
          promise = std::move(run_pipeline)]() mutable -> Poll<absl::Status> {
    auto p = promise();
    if (auto* status = p.value_if_ready()) {
      GRPC_TRACE_LOG(ext_proc_filter, INFO)
          << "ExtProcCall " << self.get()
          << " ServerToClientCall finished. status=" << *status;
      // Handle failures in the pipeline (either from the response path or the
      // error watcher).
      if (!status->ok()) {
        GRPC_TRACE_LOG(ext_proc_filter, INFO)
            << "ExtProcCall " << self.get()
            << " ServerToClientCall failed: " << *status;
        // Push error trailers to the parent call (client).
        auto error_md = CancelledServerMetadataFromStatus(*status);
        GRPC_TRACE_LOG(ext_proc_filter, INFO)
            << "ExtProcCall " << self.get()
            << ": Pushing server trailing metadata downstream (error)";
        self->handler_.SpawnPushServerTrailingMetadata(std::move(error_md));
        // Cancel the child call to the backend server.
        self->initiator_.Cancel();
        // Close the ext_proc stream.
        self->CloseStream();
      }
      return *status;
    }
    return Pending{};
  };
}

absl::AnyInvocable<Poll<absl::Status>()> ExtProcFilter::ExtProcCall::Call() {
  return If(
      !ext_proc_filter_->config_->processing_mode->send_request_headers,
      [self = Ref()]() mutable {
        return self->ClientToServerCallNonProcessingMode();
      },
      [self = Ref()]() mutable {
        return If(
            self->ext_proc_filter_->config_->observability_mode,
            [self]() mutable {
              return self->ClientToServerObservabilityMode();
            },
            [self]() mutable { return self->ClientToServerCallNormalMode(); });
      });
}

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
            ext_proc_filter, std::move(transport), handler);
        return ArenaPromise<absl::Status>(ext_proc_call->Call());
      });
}

}  // namespace grpc_core
