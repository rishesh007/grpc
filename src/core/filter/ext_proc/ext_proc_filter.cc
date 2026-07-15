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
#include <string>

#include "src/core/call/call_spine.h"
#include "src/core/call/message.h"
#include "src/core/call/metadata.h"
#include "src/core/client_channel/client_channel_args.h"
#include "src/core/config/core_configuration.h"
#include "src/core/filter/ext_proc/ext_proc_messages.h"
#include "src/core/lib/promise/if.h"
#include "src/core/lib/promise/inter_activity_latch.h"
#include "src/core/lib/promise/map.h"
#include "src/core/lib/promise/prioritized_race.h"
#include "src/core/lib/promise/seq.h"
#include "src/core/lib/promise/try_join.h"
#include "src/core/lib/promise/try_seq.h"
#include "src/core/lib/resource_quota/arena.h"
#include "src/core/util/match.h"
#include "src/core/util/string.h"
#include "src/core/xds/grpc/xds_common_types.h"
#include "src/core/xds/xds_client/serialized_streaming_call.h"
#include "absl/strings/str_join.h"

namespace grpc_core {

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
          StrAppend(result, "grpc_service=");
          StrAppend(result, channel->server()->Key());
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

//
// ExtProcFilter::ExtProcChannel
//

ExtProcFilter::ExtProcChannel::ExtProcChannel(
    std::shared_ptr<const XdsBootstrap::XdsServerTarget> server,
    RefCountedPtr<XdsTransportFactory> transport_factory)
    : server_(std::move(server)),
      transport_factory_(std::move(transport_factory)) {
  GRPC_TRACE_LOG(ext_proc_filter, INFO)
      << "creating channel " << this << " for server " << server_->server_uri();
}

ExtProcFilter::ExtProcChannel::~ExtProcChannel() {
  GRPC_TRACE_LOG(ext_proc_filter, INFO)
      << "destroying ext_proc channel " << this << " for server "
      << server_->server_uri();
}

absl::StatusOr<RefCountedPtr<XdsTransportFactory::XdsTransport>>
ExtProcFilter::ExtProcChannel::GetTransport() {
  absl::Status status;
  auto transport = transport_factory_->GetTransport(*server_, &status);
  if (!status.ok()) {
    return status;
  }
  if (transport == nullptr) {
    return absl::InternalError("Failed to get transport (returned nullptr)");
  }
  return transport;
}
//
// ExtProcFilter::ExtProcCall
//

class ExtProcFilter::ExtProcCall : public DualRefCounted<ExtProcCall> {
 public:
  ExtProcCall(RefCountedPtr<XdsTransportFactory::XdsTransport> transport,
              RefCountedPtr<const Config> config)
      : config_(std::move(config)), transport_(std::move(transport)) {
    const char* method = "/envoy.service.ext_proc.v3.ExternalProcessor/Process";
    streaming_call_ = MakeOrphanable<SerializedStreamingCall>(
        transport_, method, std::make_unique<StreamEventHandler>(WeakRef()),
        /*wait_for_ready=*/false);
    streaming_call_->StartRecvMessage();
  }

  ~ExtProcCall() override {
    if (deferred_close_timeout() != Duration::Zero() && observability_mode()) {
      auto ee = grpc_event_engine::experimental::GetDefaultEventEngine();
      ee->RunAfter(deferred_close_timeout(),
                   [call = std::move(streaming_call_),
                    transport = std::move(transport_)]() mutable {
                     call.reset();
                     transport.reset();
                   });
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
    MutexLock lock(&mu_);
    bool is_first = is_first_message_on_ext_proc_stream_;
    is_first_message_on_ext_proc_stream_ = false;
    return is_first;
  }

  bool IsClientFailOpenAllowed() const {
    MutexLock lock(&mu_);
    if (observability_mode()) return failure_mode_allow();
    return failure_mode_allow() && !c2s_first_body_message_sent_;
  }

  bool IsServerFailOpenAllowed() const {
    MutexLock lock(&mu_);
    if (observability_mode()) return failure_mode_allow();
    return failure_mode_allow() && !s2c_first_body_message_sent_;
  }

  bool IsStreamFailOpenAllowed() const {
    MutexLock lock(&mu_);
    if (observability_mode() || !failure_mode_allow()) {
      return failure_mode_allow();
    }
    return !(c2s_first_body_message_sent_ || s2c_first_body_message_sent_);
  }

  void MarkClientHalfCloseInitiated() {
    MutexLock lock(&mu_);
    c2s_half_close_initiated_ = true;
  }

  bool IsStreamClosed() const { return stream_status_.IsSet(); }

  bool ext_proc_stream_half_closed() const {
    MutexLock lock(&mu_);
    return ext_proc_stream_half_closed_;
  }

  bool drain_requested() const {
    return drain_requested_.load(std::memory_order_acquire);
  }

  void SetDrainRequested() {
    drain_requested_.store(true, std::memory_order_release);
  }

  bool IsStreamClosedCleanly() const {
    auto status = stream_status_.Get();
    bool closed = status.has_value();
    absl::Status s = closed ? status->status : absl::OkStatus();
    GRPC_TRACE_LOG(ext_proc_filter, INFO)
        << "ExtProc: IsStreamClosedCleanly: closed=" << closed
        << ", status=" << s;
    return closed && s.ok();
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
    if (s2c_writes_done_ && outstanding_s2c_messages_ == 0) {
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
    MutexLock lock(&mu_);
    s2c_writes_done_ = true;
    if (outstanding_s2c_messages_ == 0) {
      if (!response_body_pipe_.sender.IsClosed()) {
        response_body_pipe_.sender.MarkClosed();
      }
    }
  }

  void SetIsTrailersOnly() {
    MutexLock lock(&mu_);
    is_trailers_only_ = true;
  }

  bool is_trailers_only() const {
    MutexLock lock(&mu_);
    return is_trailers_only_;
  }

  void SetServerTrailersSent() {
    MutexLock lock(&mu_);
    server_trailers_sent_ = true;
  }

  bool server_trailers_sent() const {
    MutexLock lock(&mu_);
    return server_trailers_sent_;
  }

  bool ext_proc_set_eos() const {
    MutexLock lock(&mu_);
    return ext_proc_set_eos_;
  }

  void SetClientSendsDone() {
    MutexLock lock(&mu_);
    c2s_writes_done_ = true;
  }

  bool c2s_write_done() const {
    MutexLock lock(&mu_);
    return c2s_writes_done_;
  }

  absl::Status GetStreamStatus() const {
    auto status = stream_status_.Get();
    if (status.has_value()) {
      return status->status;
    }
    return absl::OkStatus();
  }

  auto WaitForStreamStatus() {
    return [this]() -> Poll<absl::Status> {
      if (stream_status_.IsSet()) {
        return GetStreamStatus();
      }
      auto poll = stream_status_.Wait()();
      if (auto* status = poll.value_if_ready()) {
        return status->status;
      }
      return Pending{};
    };
  }

  Mutex* mu() ABSL_LOCK_RETURNED(mu_) { return &mu_; }

  absl::AnyInvocable<Poll<absl::Status>()> SendMessage(
      absl::AnyInvocable<absl::StatusOr<std::string>()> payload_generator) {
    MutexLock lock(&mu_);
    if (stream_status_.IsSet() || streaming_call_ == nullptr) {
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
    OrphanablePtr<SerializedStreamingCall> streaming_call;
    {
      MutexLock lock(&mu_);
      if (!stream_status_.IsSet()) {
        stream_status_.Set(CopyableStatus(absl::OkStatus()));
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

 private:
  class StreamEventHandler final
      : public XdsTransportFactory::XdsTransport::StreamingCall::EventHandler {
   public:
    explicit StreamEventHandler(WeakRefCountedPtr<ExtProcCall> call)
        : call_(std::move(call)) {}

    void OnRequestSent(bool ok) override {
      if (auto call = call_->RefIfNonZero(); call != nullptr) {
        call->OnRequestSent(ok);
      }
    }

    void OnRecvMessage(absl::string_view payload) override {
      if (auto call = call_->RefIfNonZero(); call != nullptr) {
        call->OnRecvMessage(payload);
      }
    }

    void OnStatusReceived(absl::Status status) override {
      if (auto call = call_->RefIfNonZero(); call != nullptr) {
        call->OnStatusReceived(std::move(status));
      }
    }

   private:
    WeakRefCountedPtr<ExtProcCall> call_;
  };

  void CompleteAllLatchesAndPipes(absl::StatusOr<ExtProcResponse> response) {
    if (processing_mode().send_request_headers &&
        !request_headers_latch_.IsSet()) {
      request_headers_latch_.Set(response);
    }
    if (processing_mode().send_response_headers &&
        !response_headers_latch_.IsSet()) {
      response_headers_latch_.Set(response);
    }
    if (processing_mode().send_response_trailers &&
        !response_trailers_latch_.IsSet()) {
      response_trailers_latch_.Set(response);
    }
    if (processing_mode().send_request_body &&
        !request_body_pipe_.sender.IsClosed()) {
      if (!response.ok()) {
        request_body_pipe_.sender.Push(response.status())();
      }
      request_body_pipe_.sender.MarkClosed();
    }
    if (processing_mode().send_response_body &&
        !response_body_pipe_.sender.IsClosed()) {
      if (!response.ok()) {
        response_body_pipe_.sender.Push(response.status())();
      }
      response_body_pipe_.sender.MarkClosed();
    }
  }

  void SetStreamStatus(absl::Status status) {
    MutexLock lock(&mu_);
    if (!stream_status_.IsSet()) {
      stream_status_.Set(CopyableStatus(status));
    }
  }

  void SetExtProcSetEos() {
    MutexLock lock(&mu_);
    ext_proc_set_eos_ = true;
  }

  void OnRequestSent(bool ok) {}

  void OnRecvMessage(absl::string_view payload) {
    // In observability mode, we only log the message and ignore it.
    // We must continue reading the stream to keep it alive.
    if (observability_mode()) {
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
    const bool fail_open = IsStreamFailOpenAllowed();
    GRPC_TRACE_LOG(ext_proc_filter, INFO)
        << "ExtProcCall " << this
        << " message received, size=" << payload.size();
    // Parse the response from the external processor.
    auto parsed_response_or = ExtProcResponse::Parse(payload);
    if (!parsed_response_or.ok()) {
      // If parsing fails, we either fail the stream or close it cleanly
      // (fail-open) depending on configuration.
      if (!fail_open) {
        SetStreamError(parsed_response_or.status());
      } else {
        CompleteAllLatchesAndPipes(ExtProcResponse{});
        CloseStream();
      }
      return;
    }
    auto parsed_response = std::move(*parsed_response_or);
    // If the server requests a drain, we half-close the stream to signal
    // we are done sending requests.
    if (parsed_response.request_drain) {
      GRPC_TRACE_LOG(ext_proc_filter, INFO)
          << "ExtProcCall " << this << " received request_drain=true";
      SetDrainRequested();
      {
        MutexLock lock(&mu_);
        ext_proc_stream_half_closed_ = true;
        if (streaming_call_ != nullptr) {
          GRPC_TRACE_LOG(ext_proc_filter, INFO)
              << "ExtProcCall " << this << " sending half-close";
          streaming_call_->SendHalfClose();
        }
      }
    }
    // Dispatch the parsed response to the appropriate latch based on the
    // response type.
    if (std::holds_alternative<ExtProcResponse::ImmediateResponse>(
            parsed_response.response)) {
      if (disable_immediate_response() || !server_trailers_sent()) {
        auto error = absl::InternalError(
            disable_immediate_response()
                ? "unhandled immediate response due to config disabled it"
                : "Immediate response received but trailers not sent to "
                  "ext_proc");
        SetStreamStatus(error);
        CompleteAllLatchesAndPipes(error);
        CloseStream();
        return;
      }
      if (processing_mode().send_response_trailers &&
          !response_trailers_latch_.IsSet()) {
        response_trailers_latch_.Set(std::move(parsed_response));
      }
      return;
    } else if (std::holds_alternative<ExtProcResponse::RequestHeaders>(
                   parsed_response.response)) {
      if (!processing_mode().send_request_headers) {
        SetStreamError(
            absl::InternalError("Received request headers response but "
                                "request headers are disabled"));
        return;
      }
      if (processing_mode().send_request_headers &&
          !request_headers_latch_.IsSet()) {
        request_headers_latch_.Set(std::move(parsed_response));
      }
    } else if (std::holds_alternative<ExtProcResponse::ResponseHeaders>(
                   parsed_response.response)) {
      if (!processing_mode().send_response_headers) {
        SetStreamError(
            absl::InternalError("Received response headers response but "
                                "response headers are disabled"));
        return;
      }
      if (processing_mode().send_response_headers &&
          !response_headers_latch_.IsSet()) {
        response_headers_latch_.Set(std::move(parsed_response));
      }
    } else if (std::holds_alternative<ExtProcResponse::ResponseTrailers>(
                   parsed_response.response)) {
      if (!processing_mode().send_response_trailers) {
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
      if (processing_mode().send_response_headers &&
          !response_headers_latch_.IsSet()) {
        SetStreamError(
            absl::InternalError("Received response trailers response before "
                                "response headers response"));
        return;
      }
      bool s2c_body_outstanding = false;
      {
        MutexLock lock(&mu_);
        if (processing_mode().send_response_body &&
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
      if (processing_mode().send_response_trailers &&
          !response_trailers_latch_.IsSet()) {
        response_trailers_latch_.Set(std::move(parsed_response));
      }
    } else if (std::holds_alternative<ExtProcResponse::RequestBody>(
                   parsed_response.response)) {
      if (!processing_mode().send_request_body) {
        SetStreamError(absl::InternalError(
            "Received request body response but request body is disabled"));
        return;
      }
      if (processing_mode().send_request_headers &&
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
      const auto& request_body =
          std::get<ExtProcResponse::RequestBody>(parsed_response.response);
      GRPC_TRACE_LOG(ext_proc_filter, INFO)
          << "ExtProc: Parsed request body response, eos: "
          << request_body.mutation.end_of_stream << ", eos_without_msg: "
          << request_body.mutation.end_of_stream_without_message;
      if (request_body.mutation.end_of_stream_without_message) {
        if (!c2s_write_done()) {
          SetStreamError(
              absl::InternalError("Client sends closed by external processor"));
          return;
        }
        SetExtProcSetEos();
        if (!request_body_pipe_.sender.IsClosed()) {
          request_body_pipe_.sender.MarkClosed();
        }
        return;
      }
      request_body_pipe_.sender.Push(std::move(parsed_response))();
      if (request_body.mutation.end_of_stream) {
        SetExtProcSetEos();
        if (!request_body_pipe_.sender.IsClosed()) {
          request_body_pipe_.sender.MarkClosed();
        }
      }
    } else if (std::holds_alternative<ExtProcResponse::ResponseBody>(
                   parsed_response.response)) {
      if (!processing_mode().send_response_body) {
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
      if (processing_mode().send_response_headers &&
          !response_headers_latch_.IsSet()) {
        SetStreamError(
            absl::InternalError("Received response body response before "
                                "response headers response"));
        return;
      }
      if (processing_mode().send_response_trailers &&
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
      // Push the message to the pipe BEFORE decrementing the outstanding count.
      // This prevents a race where SetServerToClientWritesDone() runs
      // concurrently, sees the outstanding count is 0, and closes the pipe
      // before we can push this last message.
      response_body_pipe_.sender.Push(std::move(parsed_response))();
      bool should_close = false;
      DecrementOutstandingServerToClientMessages(&should_close);
      if (should_close) {
        // If writes are done and this was the last outstanding message, we can
        // close the pipe early to signal completion to the read loop.
        if (!response_body_pipe_.sender.IsClosed()) {
          response_body_pipe_.sender.MarkClosed();
        }
      }
    }
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
        !observability_mode() && (processing_mode().send_request_body ||
                                  processing_mode().send_response_body);
    const bool drain_requested =
        drain_requested_.load(std::memory_order_relaxed);
    if (status.ok()) {
      if (must_drain && !drain_requested) {
        status = absl::InternalError("Stream closed cleanly without drain");
      } else if (has_outstanding_messages && !observability_mode()) {
        status = absl::InternalError(
            "Stream closed cleanly with outstanding messages");
      }
    }
    const bool fail_open_allowed = IsStreamFailOpenAllowed();
    const bool should_propagate_error = !status.ok() && !fail_open_allowed;
    bool already_closed = false;
    {
      MutexLock lock(&mu_);
      already_closed = stream_status_.IsSet();
      if (!already_closed) {
        stream_status_.Set(CopyableStatus(status));
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

 public:
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
          upb::Arena serialization_arena;
          return CreateExtProcServerHeadersRequest(
              serialization_arena.ptr(), metadata->get(),
              config->forwarding_allowed_headers,
              config->forwarding_disallowed_headers,
              /*attributes=*/nullptr, config->observability_mode,
              processing_mode, end_of_stream);
        });
  }

  auto SendServerMessageRequest(const MessageHandle& message) {
    if (!observability_mode()) {
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
          ext_proc_call->mu()->AssertHeld();
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
            MutexLock lock(ext_proc_call->mu());
            ext_proc_call->s2c_first_body_message_sent_ = true;
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
                upb::Arena serialization_arena;
                return CreateExtProcServerTrailersRequest(
                    serialization_arena.ptr(), metadata->get(),
                    ext_proc_call->config()->forwarding_allowed_headers,
                    ext_proc_call->config()->forwarding_disallowed_headers,
                    /*attributes=*/nullptr,
                    /*observability_mode=*/false, processing_mode);
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
    if (!observability_mode()) {
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
          ext_proc_call->mu()->AssertHeld();
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
            MutexLock lock(ext_proc_call->mu());
            ext_proc_call->c2s_first_body_message_sent_ = true;
          }
          return status;
        });
  }

 private:
  InterActivityLatch<absl::StatusOr<ExtProcResponse>> request_headers_latch_;
  InterActivityLatch<absl::StatusOr<ExtProcResponse>> response_headers_latch_;
  InterActivityLatch<absl::StatusOr<ExtProcResponse>> response_trailers_latch_;
  InterActivityPipe<absl::StatusOr<ExtProcResponse>, 16> request_body_pipe_;
  InterActivityPipe<absl::StatusOr<ExtProcResponse>, 16> response_body_pipe_;

  RefCountedPtr<const Config> config_;

  bool observability_mode() const { return config_->observability_mode; }
  bool failure_mode_allow() const {
    return config_->failure_mode_allow.value_or(false);
  }
  bool disable_immediate_response() const {
    return config_->disable_immediate_response;
  }
  ProcessingMode processing_mode() const {
    return config_->processing_mode.value_or(ProcessingMode());
  }
  Duration deferred_close_timeout() const {
    return config_->deferred_close_timeout;
  }
  std::atomic<bool> drain_requested_{false};

  bool is_first_message_on_ext_proc_stream_ ABSL_GUARDED_BY(&mu_) = true;

  bool c2s_first_body_message_sent_ ABSL_GUARDED_BY(&mu_) = false;
  bool s2c_first_body_message_sent_ ABSL_GUARDED_BY(&mu_) = false;

  size_t outstanding_s2c_messages_ ABSL_GUARDED_BY(&mu_) = 0;
  size_t outstanding_c2s_messages_ ABSL_GUARDED_BY(&mu_) = 0;

  bool c2s_writes_done_ ABSL_GUARDED_BY(&mu_) = false;
  bool s2c_writes_done_ ABSL_GUARDED_BY(&mu_) = false;
  bool c2s_half_close_initiated_ ABSL_GUARDED_BY(&mu_) = false;
  bool is_trailers_only_ ABSL_GUARDED_BY(&mu_) = false;
  bool server_trailers_sent_ ABSL_GUARDED_BY(&mu_) = false;

  bool ext_proc_set_eos_ ABSL_GUARDED_BY(&mu_) = false;
  bool ext_proc_stream_half_closed_ ABSL_GUARDED_BY(&mu_) = false;

  // Helper struct to wrap absl::Status.
  // InterActivityLatch::Wait() moves the value out of the latch, which would
  // leave it in an invalid (moved-from) state for subsequent reads. Since
  // multiple promises need to query the stream status from ExtProcCall, we
  // override the move constructor/assignment to perform a copy instead,
  // ensuring the status remains valid for all readers.
  struct CopyableStatus {
    absl::Status status;
    CopyableStatus() = default;
    explicit CopyableStatus(absl::Status s) : status(std::move(s)) {}
    CopyableStatus(const CopyableStatus&) = default;
    CopyableStatus(CopyableStatus&& other) noexcept : status(other.status) {}
    CopyableStatus& operator=(const CopyableStatus&) = default;
    CopyableStatus& operator=(CopyableStatus&& other) noexcept {
      status = other.status;
      return *this;
    }
  };

  InterActivityLatch<CopyableStatus> stream_status_;

  mutable Mutex mu_;

  RefCountedPtr<XdsTransportFactory::XdsTransport> transport_;
  OrphanablePtr<SerializedStreamingCall> streaming_call_;
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

absl::AnyInvocable<Poll<absl::Status>()> ServerInitialMetadataNormalMode(
    CallHandler handler, CallInitiator initiator,
    RefCountedPtr<ExtProcFilter::ExtProcCall> ext_proc_call,
    std::shared_ptr<ServerMetadataHandle> metadata) {
  GRPC_TRACE_LOG(ext_proc_filter, INFO)
      << "ExtProc: ServerInitialMetadataNormalMode pulled. metadata: "
      << (*metadata)->DebugString();
  // If a drain has been requested, we bypass sending the server initial
  // metadata to the external processor. Instead, we wait for the ext_proc
  // stream to close (drain complete) before propagating the metadata
  // downstream, subject to fail-open/fail-closed.
  return If(
      ext_proc_call->drain_requested(),
      [ext_proc_call, handler, metadata]() mutable {
        GRPC_TRACE_LOG(ext_proc_filter, INFO)
            << "ExtProc: Drain active before sending Server Initial Metadata, "
               "blocking propagation";
        return Map(
            ext_proc_call->WaitForStreamStatus(),
            [ext_proc_call, handler,
             metadata](absl::Status status) mutable -> absl::Status {
              GRPC_TRACE_LOG(ext_proc_filter, INFO)
                  << "ExtProc: Server Initial Metadata Drain complete "
                     "(pre-existing). Status: "
                  << status;
              if (!ext_proc_call->IsStreamClosedCleanly() &&
                  !ext_proc_call->IsServerFailOpenAllowed()) {
                return status;
              }
              handler.SpawnPushServerInitialMetadata(std::move(*metadata));
              return absl::OkStatus();
            });
      },
      [ext_proc_call, handler, metadata]() mutable {
        return TrySeq(
            ext_proc_call->SendServerInitialMetadataRequest(metadata),
            ext_proc_call->response_headers_latch().Wait(),
            [metadata, handler,
             ext_proc_call](ExtProcResponse response) mutable -> absl::Status {
              if (const auto* headers =
                      std::get_if<ExtProcResponse::ResponseHeaders>(
                          &response.response);
                  headers != nullptr) {
                const auto& response_headers = headers->mutation;
                const auto* rules =
                    ext_proc_call->config()->mutation_rules.has_value()
                        ? &ext_proc_call->config()->mutation_rules.value()
                        : nullptr;
                auto status =
                    ApplyHeaderMutations(response_headers, rules, **metadata);
                if (!status.ok()) {
                  return status;
                }
              }
              GRPC_TRACE_LOG(ext_proc_filter, INFO)
                  << "ExtProc: Pushing server initial metadata downstream";
              handler.SpawnPushServerInitialMetadata(std::move(*metadata));
              return absl::OkStatus();
            });
      });
}

auto ServerInitialMetadataObservabilityMode(
    CallHandler handler,
    RefCountedPtr<ExtProcFilter::ExtProcCall> ext_proc_call,
    std::shared_ptr<ServerMetadataHandle> metadata) {
  GRPC_TRACE_LOG(ext_proc_filter, INFO)
      << "ExtProc: ServerInitialMetadataObservabilityMode pulled. metadata: "
      << (*metadata)->DebugString();
  return Map(
      ext_proc_call->SendServerInitialMetadataRequest(
          metadata, /*end_of_stream=*/ext_proc_call->is_trailers_only()),
      [handler, metadata, ext_proc_call = std::move(ext_proc_call)](
          absl::Status status) mutable -> absl::Status {
        if (!status.ok() && !ext_proc_call->config()->failure_mode_allow) {
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
        if (ext_proc_call->is_trailers_only()) {
          handler.SpawnPushServerTrailingMetadata(std::move(*metadata));
        } else {
          handler.SpawnPushServerInitialMetadata(std::move(*metadata));
        }
        return absl::OkStatus();
      });
}

absl::AnyInvocable<Poll<absl::Status>()> ServerInitialMetadata(
    CallHandler handler, CallInitiator initiator,
    RefCountedPtr<ExtProcFilter::ExtProcCall> ext_proc_call,
    std::shared_ptr<ServerMetadataHandle> metadata) {
  const bool send_headers =
      ext_proc_call->config()
          ->processing_mode.value_or(ExtProcProcessingMode())
          .send_response_headers &&
      ext_proc_call != nullptr && !ext_proc_call->IsStreamClosed() &&
      !ext_proc_call->ext_proc_stream_half_closed();
  absl::AnyInvocable<Poll<absl::Status>()> promise;
  if (!send_headers) {
    promise = [handler, ext_proc_call = std::move(ext_proc_call),
               metadata]() mutable {
      if (ext_proc_call != nullptr && ext_proc_call->IsStreamClosed() &&
          !ext_proc_call->IsStreamClosedCleanly() &&
          !ext_proc_call->IsStreamFailOpenAllowed()) {
        return ext_proc_call->GetStreamStatus();
      }
      GRPC_TRACE_LOG(ext_proc_filter, INFO)
          << "ExtProc: ServerInitialMetadataNonProcessingMode metadata: "
          << (*metadata)->DebugString();
      handler.SpawnPushServerInitialMetadata(std::move(*metadata));
      return absl::OkStatus();
    };
  } else if (ext_proc_call->config()->observability_mode) {
    auto p = ServerInitialMetadataObservabilityMode(
        handler, std::move(ext_proc_call), std::move(metadata));
    promise = [p = std::move(p)]() mutable { return p(); };
  } else {
    auto p = ServerInitialMetadataNormalMode(
        handler, initiator, std::move(ext_proc_call), std::move(metadata));
    promise = [p = std::move(p)]() mutable { return p(); };
  }
  return promise;
}

auto ServerToClientMessagesObservabilityMode(
    CallHandler handler, CallInitiator initiator,
    RefCountedPtr<ExtProcFilter::ExtProcCall> ext_proc_call) {
  GRPC_TRACE_LOG(ext_proc_filter, INFO)
      << "ExtProc: ServerToClientMessagesObservabilityMode started, "
      << "stream_closed=" << ext_proc_call->IsStreamClosed();
  return ForEach(MessagesFrom(initiator), [handler, ext_proc_call](
                                              MessageHandle message) mutable {
    const bool stream_closed = ext_proc_call->IsStreamClosed();
    GRPC_TRACE_LOG(ext_proc_filter, INFO)
        << "ExtProc: ServerToClientMessagesObservabilityMode "
           "processing message, stream_closed="
        << stream_closed;
    return Map(
        If(
            !stream_closed,
            [ext_proc_call, &message]() {
              return ext_proc_call->SendServerMessageRequest(message);
            },
            []() -> absl::Status { return absl::OkStatus(); }),
        [handler, message = std::move(message),
         ext_proc_call](absl::Status status) mutable -> absl::Status {
          const bool failure_mode_allow =
              ext_proc_call->config()->failure_mode_allow.value_or(false);
          if (!status.ok() && !failure_mode_allow) {
            if (ext_proc_call->IsStreamClosedCleanly()) {
              GRPC_TRACE_LOG(ext_proc_filter, INFO)
                  << "ExtProc: Ignored server message send failure in "
                     "observability mode due to clean close: "
                  << status;
            } else {
              return status;
            }
          }
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
                            !ext_proc_call->IsServerFailOpenAllowed()) {
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
                          ->processing_mode.value_or(ExtProcProcessingMode())
                          .send_response_body &&
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
                                    !ext_proc_call->IsServerFailOpenAllowed()) {
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
                        bool fail_open =
                            ext_proc_call->IsServerFailOpenAllowed();
                        GRPC_TRACE_LOG(ext_proc_filter, INFO)
                            << "ExtProc: S2C bypass check: is_closed="
                            << is_closed << ", is_clean=" << is_clean
                            << ", fail_open=" << fail_open;
                        if (ext_proc_call->config()
                                ->processing_mode
                                .value_or(ExtProcProcessingMode())
                                .send_response_body &&
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
  auto promise =
      Map(TryJoin<absl::StatusOr>(
              SendServerToClientMessagesToExtProcServer(handler, initiator,
                                                        ext_proc_call),
              ReadServerToClientMessagesFromExtProcServer(
                  handler, initiator, std::move(ext_proc_call))),
          [](auto result) -> absl::Status { return result.status(); });
  return [promise = std::move(promise)]() mutable { return promise(); };
}

absl::AnyInvocable<Poll<absl::Status>()> ServerToClientMessages(
    CallHandler handler, CallInitiator initiator,
    RefCountedPtr<ExtProcFilter::ExtProcCall> ext_proc_call) {
  const bool send_body = ext_proc_call->config()
                             ->processing_mode.value_or(ExtProcProcessingMode())
                             .send_response_body &&
                         !ext_proc_call->IsStreamClosed();
  absl::AnyInvocable<Poll<absl::Status>()> promise;
  if (!send_body) {
    GRPC_TRACE_LOG(ext_proc_filter, INFO)
        << "ExtProc: ServerToClientMessagesNonProcessingMode started";
    auto p = ForEach(MessagesFrom(initiator),
                     [handler](MessageHandle message) mutable {
                       GRPC_TRACE_LOG(ext_proc_filter, INFO)
                           << "ExtProc: "
                              "ServerToClientMessagesNonProcessingMode "
                              "forwarding message";
                       handler.SpawnPushMessage(std::move(message));
                       return absl::OkStatus();
                     });
    promise = [p = std::move(p)]() mutable { return p(); };
  } else if (ext_proc_call->config()->observability_mode) {
    auto p = ServerToClientMessagesObservabilityMode(handler, initiator,
                                                     std::move(ext_proc_call));
    promise = [p = std::move(p)]() mutable { return p(); };
  } else {
    promise = ServerToClientMessagesNormalMode(handler, initiator,
                                               std::move(ext_proc_call));
  }
  return promise;
}

absl::AnyInvocable<Poll<absl::Status>()>
ReadServerTrailingMetadataFromExtProcServer(
    CallHandler handler, CallInitiator initiator,
    RefCountedPtr<ExtProcFilter::ExtProcCall> ext_proc_call,
    std::shared_ptr<ServerMetadataHandle> metadata) {
  auto config = ext_proc_call->config();
  GRPC_TRACE_LOG(ext_proc_filter, INFO)
      << "ExtProc: ReadServerTrailingMetadataFromExtProcServer started";
  return Map(
      // Wait on response_trailers_latch, which is set when the external
      // processor returns the response to our ServerTrailingMetadata
      // request (or when the stream terminates/fails).
      ext_proc_call->response_trailers_latch().Wait(),
      [handler, metadata, ext_proc_call, config, initiator](
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
            const auto& immediate_response = *immediate;
            auto error_md = CancelledServerMetadataFromStatus(
                static_cast<grpc_status_code>(immediate_response.status),
                immediate_response.details);
            const auto* rules = config->mutation_rules.has_value()
                                    ? &config->mutation_rules.value()
                                    : nullptr;
            auto mut_status = ApplyHeaderMutations(
                immediate_response.header_mutation, rules, *error_md);
            if (!mut_status.ok()) {
              GRPC_TRACE_LOG(ext_proc_filter, ERROR)
                  << "Failed to apply immediate response header mutations: "
                  << mut_status;
            }
            *metadata = std::move(error_md);
            GRPC_TRACE_LOG(ext_proc_filter, INFO)
                << "ExtProc: ServerTrailingMetadata pushing immediate response "
                   "metadata";
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
          if (config->processing_mode.value_or(ExtProcProcessingMode())
                  .send_response_body &&
              !config->observability_mode &&
              !ext_proc_call->response_body_pipe().sender.IsClosed()) {
            ext_proc_call->response_body_pipe().sender.MarkClosed();
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
        handler.SpawnPushServerTrailingMetadata(std::move(*metadata));
        return absl::OkStatus();
      });
}

absl::AnyInvocable<Poll<absl::Status>()> ServerTrailingMetadataNormalMode(
    CallHandler handler, CallInitiator initiator,
    RefCountedPtr<ExtProcFilter::ExtProcCall> ext_proc_call,
    std::shared_ptr<ServerMetadataHandle> metadata) {
  GRPC_TRACE_LOG(ext_proc_filter, INFO)
      << "ExtProc: ServerTrailingMetadataNormalMode pulled. metadata: "
      << (*metadata)->DebugString();
  // If a drain has been requested, we bypass sending the server trailing
  // metadata to the external processor. Instead, we wait for the ext_proc
  // stream to close (drain complete) before propagating the metadata
  // downstream, subject to fail-open/fail-closed policies.
  return If(
      ext_proc_call->drain_requested(),
      [ext_proc_call, handler, metadata]() mutable {
        GRPC_TRACE_LOG(ext_proc_filter, INFO)
            << "ExtProc: Drain active before sending Server Trailing Metadata, "
               "blocking propagation";
        return Map(
            ext_proc_call->WaitForStreamStatus(),
            [ext_proc_call, handler,
             metadata](absl::Status status) mutable -> absl::Status {
              GRPC_TRACE_LOG(ext_proc_filter, INFO)
                  << "ExtProc: Server Trailing Metadata Drain complete "
                     "(pre-existing). Status: "
                  << status;
              if (!ext_proc_call->IsStreamClosedCleanly() &&
                  !ext_proc_call->IsServerFailOpenAllowed()) {
                return status;
              }
              handler.SpawnPushServerTrailingMetadata(std::move(*metadata));
              return absl::OkStatus();
            });
      },
      [ext_proc_call, handler, metadata, initiator]() mutable {
        return Seq(ext_proc_call->SendServerTrailingMetadataRequest(metadata),
                   [handler, initiator, ext_proc_call = ext_proc_call->Ref(),

                    metadata](absl::Status /*send_status*/) mutable {
                     return ReadServerTrailingMetadataFromExtProcServer(
                         handler, initiator, std::move(ext_proc_call),
                         std::move(metadata));
                   });
      });
}

absl::AnyInvocable<Poll<absl::Status>()>
ServerTrailingMetadataObservabilityMode(
    CallHandler handler,
    RefCountedPtr<ExtProcFilter::ExtProcCall> ext_proc_call,
    std::shared_ptr<ServerMetadataHandle> metadata) {
  GRPC_TRACE_LOG(ext_proc_filter, INFO)
      << "ExtProc: ServerTrailingMetadataObservabilityMode pulled. metadata: "
      << (*metadata)->DebugString();
  // Asynchronously send the ServerTrailers message to the external processor
  // provided the ext_proc stream is still open. In observability mode, traffic
  // is strictly observed and not modified.
  absl::AnyInvocable<Poll<absl::Status>()> send_promise;
  if (!ext_proc_call->IsStreamClosed()) {
    const bool is_first_message = ext_proc_call->IsFirstMessageOnStream();
    send_promise = ext_proc_call->SendMessage([ext_proc_call, metadata,
                                               is_first_message]() {
      GRPC_TRACE_LOG(ext_proc_filter, INFO)
          << "ExtProc: Sending server trailing metadata (observability mode)";
      upb::Arena serialization_arena;
      std::optional<ExtProcProcessingMode> processing_mode;
      if (is_first_message) {
        processing_mode = ext_proc_call->config()->processing_mode;
      }
      return CreateExtProcServerTrailersRequest(
          serialization_arena.ptr(), metadata->get(),
          ext_proc_call->config()->forwarding_allowed_headers,
          ext_proc_call->config()->forwarding_disallowed_headers,
          /*attributes=*/nullptr, /*observability_mode=*/true, processing_mode);
    });
  } else {
    send_promise = []() -> Poll<absl::Status> { return absl::OkStatus(); };
  }
  return Seq(
      std::move(send_promise),
      [handler, metadata,
       ext_proc_call = std::move(ext_proc_call)](absl::Status status) mutable {
        // Ensure the response body pipe sender is marked closed when trailing
        // metadata arrives, cleanly terminating any ongoing asynchronous read
        // loops.
        if (ext_proc_call->config()
                ->processing_mode.value_or(ExtProcProcessingMode())
                .send_response_body &&
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
            !ext_proc_call->config()->failure_mode_allow.value_or(false)) {
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
  if (ext_proc_call->config()
          ->processing_mode.value_or(ExtProcProcessingMode())
          .send_response_body &&
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
    RefCountedPtr<ExtProcFilter::ExtProcCall> ext_proc_call,
    std::shared_ptr<ServerMetadataHandle> metadata) {
  GRPC_TRACE_LOG(ext_proc_filter, INFO)
      << "ExtProc: ServerTrailingMetadataTrailersOnlyNormalMode started";
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
                  !ext_proc_call->IsServerFailOpenAllowed()) {
                return status;
              }
              handler.SpawnPushServerTrailingMetadata(std::move(*metadata));
              return absl::OkStatus();
            });
      },
      [ext_proc_call, handler, metadata, initiator]() mutable {
        return TrySeq(
            // Send the trailers-only metadata as ServerHeaders (with
            // end_of_stream=true).
            ext_proc_call->SendServerInitialMetadataRequest(
                metadata,
                /*end_of_stream=*/true),
            [handler, initiator, ext_proc_call = std::move(ext_proc_call),
             metadata]() mutable {
              const auto* rules =
                  ext_proc_call->config()->mutation_rules.has_value()
                      ? &ext_proc_call->config()->mutation_rules.value()
                      : nullptr;
              return Map(
                  // Wait for response headers (which will contain the external
                  // processor's decision on our ServerHeaders request).
                  ext_proc_call->response_headers_latch().Wait(),
                  [rules, metadata, ext_proc_call, initiator,
                   handler](absl::StatusOr<ExtProcResponse> response) mutable
                      -> absl::Status {
                    absl::Status status = absl::OkStatus();
                    if (!response.ok()) {
                      status = response.status();
                    } else if (const auto* headers = std::get_if<
                                   ExtProcResponse::ResponseHeaders>(
                                   &response->response);
                               headers != nullptr) {
                      // Apply header mutations from the external processor's
                      // response to our trailing metadata.
                      status = ApplyHeaderMutations(headers->mutation, rules,
                                                    **metadata);
                    }
                    // If an error occurred while waiting for or processing the
                    // response, check failure mode configuration. Unless
                    // failure_mode_allow is enabled (which allows proceeding
                    // with unmutated metadata), replace the trailing metadata
                    // with a cancelled status corresponding to the error.
                    if (!status.ok() &&
                        !ext_proc_call->config()->failure_mode_allow.value_or(
                            false)) {
                      *metadata = CancelledServerMetadataFromStatus(status);
                    }
                    // Push the final (mutated or error) server trailing
                    // metadata downstream.
                    handler.SpawnPushServerTrailingMetadata(
                        std::move(*metadata));
                    return status;
                  });
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
    if (!error.ok() && !ext_proc_call->IsServerFailOpenAllowed()) {
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
    RefCountedPtr<ExtProcFilter::ExtProcCall> ext_proc_call,
    std::shared_ptr<ServerMetadataHandle> metadata) {
  // If the ext_proc stream has closed prematurely, route immediately to
  // error propagation or unmutated fallback.
  if (auto promise =
          MaybeHandleClosedStream(handler, ext_proc_call, metadata)) {
    return std::move(*promise);
  }
  // Determine if we should attempt to send trailers-only headers to the
  // processor, which requires the config setting and an active ext_proc stream.
  const bool send_headers =
      ext_proc_call->config()
          ->processing_mode.value_or(ExtProcProcessingMode())
          .send_response_headers &&
      !ext_proc_call->IsStreamClosed() &&
      !ext_proc_call->ext_proc_stream_half_closed();
  // Route to the appropriate handler based on configuration.
  if (!send_headers) {
    return ServerTrailingMetadataNonProcessingMode(
        handler, std::move(ext_proc_call), std::move(metadata));
  } else if (ext_proc_call->config()->observability_mode) {
    return ServerInitialMetadataObservabilityMode(
        handler, std::move(ext_proc_call), std::move(metadata));
  } else {
    return ServerTrailingMetadataTrailersOnlyNormalMode(
        handler, initiator, std::move(ext_proc_call), std::move(metadata));
  }
}

// Orchestrates the server trailing metadata step for a normal RPC (one that has
// sent initial metadata and/or response body before finishing).
absl::AnyInvocable<Poll<absl::Status>()> ServerTrailingMetadataNormal(
    CallHandler handler, CallInitiator initiator,
    RefCountedPtr<ExtProcFilter::ExtProcCall> ext_proc_call,
    std::shared_ptr<ServerMetadataHandle> metadata) {
  // If the ext_proc stream has closed prematurely, route immediately to
  // error propagation or unmutated fallback.
  if (auto promise =
          MaybeHandleClosedStream(handler, ext_proc_call, metadata)) {
    return std::move(*promise);
  }
  // Determine if we should attempt to send trailers to the processor.
  // Trailers are only sent if processing is enabled in config, the backend
  // returned an OK status (errors skip trailing metadata processing), and the
  // ext_proc stream is active.
  const bool send_trailers_to_ext_proc_stream =
      ext_proc_call->config()
          ->processing_mode.value_or(ExtProcProcessingMode())
          .send_response_trailers &&
      IsStatusOk(*metadata) && !ext_proc_call->IsStreamClosed() &&
      !ext_proc_call->ext_proc_stream_half_closed();
  if (!send_trailers_to_ext_proc_stream) {
    return ServerTrailingMetadataNonProcessingMode(
        handler, std::move(ext_proc_call), std::move(metadata));
  } else if (ext_proc_call->config()->observability_mode) {
    return ServerTrailingMetadataObservabilityMode(
        handler, std::move(ext_proc_call), std::move(metadata));
  } else {
    return ServerTrailingMetadataNormalMode(
        handler, initiator, std::move(ext_proc_call), std::move(metadata));
  }
}

// Main dispatcher function for the ServerTrailingMetadata filter interceptor
// step. Distinguishes between "trailers-only" RPCs and normal RPCs and routes
// accordingly.
absl::AnyInvocable<Poll<absl::Status>()> ServerTrailingMetadata(
    CallHandler handler, CallInitiator initiator,
    RefCountedPtr<ExtProcFilter::ExtProcCall> ext_proc_call,
    std::shared_ptr<ServerMetadataHandle> metadata) {
  // Check if this response is "trailers-only" (i.e. backend ended the RPC
  // immediately without sending response headers first).
  const bool is_trailers_only =
      (*metadata)->get(GrpcTrailersOnly()).value_or(false);
  if (is_trailers_only) {
    ext_proc_call->SetIsTrailersOnly();
  }
  absl::AnyInvocable<Poll<absl::Status>()> promise;
  // Dispatch to the appropriate handler based on whether the response is
  // trailers-only.
  if (is_trailers_only) {
    promise = ServerTrailingMetadataTrailersOnly(
        handler, initiator, std::move(ext_proc_call), std::move(metadata));
  } else {
    promise = ServerTrailingMetadataNormal(
        handler, initiator, std::move(ext_proc_call), std::move(metadata));
  }
  return promise;
}

// Intercepts and processes client-to-server messages.
// This is used for both Observability Mode (asynchronous mirroring) and Normal
// Mode (when body processing is disabled, acting as a pass-through).
//
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
      [initiator]() mutable {
        GRPC_TRACE_LOG(ext_proc_filter, INFO)
            << "ExtProc: ClientToServerMessagesNonProcessingMode finished "
               "sends";
        initiator.SpawnFinishSends();
        return absl::OkStatus();
      });
}

// Handles client-to-server messages in observability mode (asynchronous
// mirroring).
absl::AnyInvocable<Poll<absl::Status>()>
ClientToServerMessagesObservabilityMode(
    CallHandler handler, CallInitiator initiator,
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
      [initiator, ext_proc_call, attributes]() mutable {
        GRPC_TRACE_LOG(ext_proc_filter, INFO)
            << "ExtProc: ClientToServerMessagesObservabilityMode finished "
               "sends";
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
                   [initiator](absl::Status status) mutable -> absl::Status {
                     if (!status.ok()) {
                       GRPC_TRACE_LOG(ext_proc_filter, INFO)
                           << "ExtProc: Failed to send client half-close in "
                              "observability mode: "
                           << status;
                     }
                     initiator.SpawnFinishSends();
                     return absl::OkStatus();
                   });
      });
}

absl::AnyInvocable<Poll<absl::Status>()> ClientToSidestreamNormalMode(
    CallHandler handler, CallInitiator initiator,
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
                                   !ext_proc_call->IsClientFailOpenAllowed()) {
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
                                    !ext_proc_call->IsClientFailOpenAllowed()) {
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
                                    !ext_proc_call->IsClientFailOpenAllowed()) {
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
                          ext_proc_call->IsClientFailOpenAllowed()) {
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
                          ext_proc_call->IsClientFailOpenAllowed()) {
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
                  if (ext_proc_call->IsClientFailOpenAllowed()) {
                    return absl::OkStatus();
                  }
                  return result.status();
                }
                auto& ext_proc_response = *result;

                // Handle request body mutation.
                if (const auto* request_body =
                        std::get_if<ExtProcResponse::RequestBody>(
                            &ext_proc_response.response)) {
                  const auto& body_mutation = request_body->mutation;
                  // Forward the mutated body to the backend server.
                  if (!body_mutation.end_of_stream_without_message) {
                    GRPC_TRACE_LOG(ext_proc_filter, INFO)
                        << "ExtProc: ClientToServerMessages playing body "
                           "mutation: "
                        << body_mutation.body.size() << "b";
                    auto slice = Slice::FromCopiedString(body_mutation.body);
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
      [initiator, ext_proc_call](absl::Status status) mutable {
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
          initiator.SpawnFinishSends();
        }
        return status;
      });
}

absl::AnyInvocable<Poll<absl::Status>()> ClientToServerMessagesNormalMode(
    CallHandler handler, CallInitiator initiator,
    RefCountedPtr<ExtProcFilter::ExtProcCall> ext_proc_call,
    ::google_protobuf_Struct* attributes) {
  return Map(
      TryJoin<absl::StatusOr>(
          ClientToSidestreamNormalMode(handler, initiator, ext_proc_call,
                                       attributes),
          SidestreamToServerNormalMode(handler, initiator, ext_proc_call)),
      [ext_proc_call = std::move(ext_proc_call)](auto result) -> absl::Status {
        GRPC_TRACE_LOG(ext_proc_filter, INFO)
            << "ClientToServerMessagesNormalMode result: " << result.status()
            << ", fail_open_allowed: "
            << ext_proc_call->IsClientFailOpenAllowed()
            << ", stream_error: " << ext_proc_call->GetStreamStatus();
        if (!result.ok()) {
          return result.status();
        }
        if (ext_proc_call->IsClientFailOpenAllowed()) {
          return absl::OkStatus();
        }
        return ext_proc_call->GetStreamStatus();
      });
}

absl::AnyInvocable<Poll<absl::Status>()> ClientToServerMessages(
    CallHandler handler, CallInitiator initiator,
    RefCountedPtr<ExtProcFilter::ExtProcCall> ext_proc_call,
    ::google_protobuf_Struct* attributes) {
  const bool send_request_body =
      ext_proc_call->config()
          ->processing_mode.value_or(ExtProcProcessingMode())
          .send_request_body &&
      !ext_proc_call->IsStreamClosed();
  if (!send_request_body) {
    return ClientToServerMessagesNonProcessingMode(handler, initiator,
                                                   std::move(ext_proc_call));
  } else if (ext_proc_call->config()->observability_mode) {
    return ClientToServerMessagesObservabilityMode(
        handler, initiator, std::move(ext_proc_call), attributes);
  } else {
    return ClientToServerMessagesNormalMode(
        handler, initiator, std::move(ext_proc_call), attributes);
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
  return MakeRefCounted<ExtProcFilter>(args, std::move(config),
                                       std::move(filter_args));
}

ExtProcFilter::ExtProcFilter(const ChannelArgs& args,
                             RefCountedPtr<const Config> config,
                             ChannelFilter::Args filter_args)
    : config_(std::move(config)),
      default_authority_(Slice::FromCopiedString(
          args.GetString(GRPC_ARG_DEFAULT_AUTHORITY)
              .value_or(
                  CoreConfiguration::Get()
                      .resolver_registry()
                      .GetDefaultAuthority(
                          args.GetString(GRPC_ARG_SERVER_URI).value_or(""))))) {
}

absl::AnyInvocable<Poll<absl::Status>()>
ExtProcFilter::ClientToServerObservabilityMode(
    CallHandler handler, RefCountedPtr<ExtProcCall> ext_proc_call) {
  return TrySeq(
      handler.PullClientInitialMetadata(),
      [self = RefAsSubclass<ExtProcFilter>(), handler,
       ext_proc_call](ClientMetadataHandle metadata) mutable
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
                shared_metadata, self->default_authority_.as_string_view()),
            [failure_mode_allow =
                 self->config()->failure_mode_allow.value_or(false),
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
            [self, handler, shared_metadata = std::move(shared_metadata),
             ext_proc_call = std::move(ext_proc_call)]() mutable
                -> absl::AnyInvocable<Poll<absl::Status>()> {
              CallInitiator initiator = self->MakeChildCall(
                  std::move(*shared_metadata), handler.arena()->Ref());
              handler.AddChildCall(initiator);
              // Spawn background task to handle server-to-client path
              // (responses).
              initiator.SpawnInfallible(
                  "server_to_client",
                  [self, handler, initiator,
                   ext_proc_call = ext_proc_call->Ref()]() mutable {
                    GRPC_TRACE_LOG(ext_proc_filter, INFO)
                        << "ExtProc: server_to_client task started";
                    return initiator.CancelIfFails(self->ServerToClientCall(
                        handler, initiator, std::move(ext_proc_call)));
                  });
              // Continue with forwarding client messages (request body).
              return ClientToServerMessages(handler, initiator,
                                            std::move(ext_proc_call),
                                            /*attributes=*/nullptr);
            });
      });
}

absl::AnyInvocable<Poll<absl::Status>()>
ExtProcFilter::ClientToServerCallNormalMode(
    CallHandler handler, RefCountedPtr<ExtProcCall> ext_proc_call) {
  return TrySeq(
      handler.PullClientInitialMetadata(),
      [self = RefAsSubclass<ExtProcFilter>(),
       ext_proc_call](ClientMetadataHandle metadata) mutable {
        GRPC_TRACE_LOG(ext_proc_filter, INFO)
            << "ExtProc: Client initial metadata received:\n"
            << metadata->DebugString();
        auto shared_metadata =
            std::make_shared<ClientMetadataHandle>(std::move(metadata));
        return Seq(
            ext_proc_call->SendClientInitialMetadataRequest(
                shared_metadata, self->default_authority_.as_string_view()),
            [shared_metadata](
                absl::Status) mutable -> absl::StatusOr<ClientMetadataHandle> {
              return std::move(*shared_metadata);
            });
      },
      [self = RefAsSubclass<ExtProcFilter>(), handler,
       ext_proc_call](ClientMetadataHandle metadata) mutable {
        return TrySeq(
            ext_proc_call->request_headers_latch().Wait(),
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
                    self->config()->mutation_rules.has_value()
                        ? &self->config()->mutation_rules.value()
                        : nullptr;
                auto status =
                    ApplyHeaderMutations(headers->mutation, rules, *metadata);
                if (!status.ok()) return status;
              }
              return std::move(metadata);
            },
            // Handle the result of response processing.
            [self, handler,
             ext_proc_call](ClientMetadataHandle metadata) mutable
                -> absl::AnyInvocable<Poll<absl::Status>()> {
              CallInitiator initiator = self->MakeChildCall(
                  std::move(metadata), handler.arena()->Ref());
              handler.AddChildCall(initiator);
              // Spawn background task to handle server-to-client path.
              initiator.SpawnInfallible(
                  "server_to_client",
                  [self, handler, initiator, ext_proc_call]() mutable {
                    GRPC_TRACE_LOG(ext_proc_filter, INFO)
                        << "ExtProc: server_to_client task started";
                    return initiator.CancelIfFails(self->ServerToClientCall(
                        handler, initiator, ext_proc_call));
                  });
              return ClientToServerMessages(handler, initiator,
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
      [self = RefAsSubclass<ExtProcFilter>(), handler,
       ext_proc_call](ClientMetadataHandle metadata) mutable
          -> absl::AnyInvocable<Poll<absl::Status>()> {
        GRPC_TRACE_LOG(ext_proc_filter, INFO)
            << "ExtProc: Client initial metadata received (non-processing):\n"
            << metadata->DebugString();
        const auto processing_mode =
            self->config()->processing_mode.value_or(ProcessingMode());
        ::google_protobuf_Struct* attributes = nullptr;
        if (processing_mode.send_request_body &&
            !self->config()->request_attributes.empty()) {
          auto* attributes_arena = handler.arena()->New<upb::Arena>();
          attributes = CreateExtProcAttributesProtoStruct(
              attributes_arena->ptr(), self->config()->request_attributes,
              *metadata, self->default_authority_.as_string_view());
        }
        CallInitiator initiator =
            self->MakeChildCall(std::move(metadata), handler.arena()->Ref());
        handler.AddChildCall(initiator);
        // Spawn background task to handle server-to-client path.
        initiator.SpawnInfallible(
            "server_to_client",
            [self, handler, initiator, ext_proc_call]() mutable {
              GRPC_TRACE_LOG(ext_proc_filter, INFO)
                  << "ExtProc: server_to_client task started";
              return initiator.CancelIfFails(
                  self->ServerToClientCall(handler, initiator, ext_proc_call));
            });
        return ClientToServerMessages(handler, initiator,
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
          [handler, initiator,
           ext_proc_call](std::optional<ServerMetadataHandle> md) mutable {
            const bool has_md = md.has_value();
            return If(
                has_md,
                [handler, initiator, ext_proc_call,
                 md = std::move(md)]() mutable {
                  auto shared_md =
                      std::make_shared<ServerMetadataHandle>(std::move(*md));
                  return TrySeq(
                      // Step 1: Intercept, send to ext_proc, and apply
                      // mutations to Server Initial Metadata.
                      ServerInitialMetadata(handler, initiator, ext_proc_call,
                                            shared_md),
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
      [handler, initiator, ext_proc_call](absl::Status status) mutable {
        if (!status.ok()) {
          // If Phase 1 failed, we propagate the error.
          return absl::AnyInvocable<Poll<absl::Status>()>(
              [status]() -> Poll<absl::Status> { return status; });
        }
        // Phase 1 succeeded. Pull and process trailing metadata.
        return absl::AnyInvocable<Poll<absl::Status>()>(Seq(
            initiator.PullServerTrailingMetadata(),
            [handler, initiator, ext_proc_call](ServerMetadataHandle md) mutable
                -> absl::AnyInvocable<Poll<absl::Status>()> {
              auto shared_md =
                  std::make_shared<ServerMetadataHandle>(std::move(md));
              // Intercept, send to ext_proc, and apply mutations to
              // Trailing Metadata.
              return ServerTrailingMetadata(handler, initiator, ext_proc_call,
                                            shared_md);
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
  CallHandler handler = Consume(std::move(unstarted_call_handler));
  if (!IsProcessingEnabled(config_->processing_mode)) {
    handler.SpawnGuarded(
        "ext_proc_bypass",
        [self = RefAsSubclass<ExtProcFilter>(), handler]() mutable {
          GRPC_TRACE_LOG(ext_proc_filter, INFO)
              << "ExtProc: No processing mode enabled, bypassing filter";
          return TrySeq(handler.PullClientInitialMetadata(),
                        [self, handler](ClientMetadataHandle metadata) mutable {
                          CallInitiator initiator = self->MakeChildCall(
                              std::move(metadata), handler.arena()->Ref());
                          handler.AddChildCall(initiator);
                          ForwardCall(handler, initiator);
                          return absl::OkStatus();
                        });
        });
    return;
  }
  handler.SpawnGuarded(
      "ext_proc_call",
      [self = RefAsSubclass<ExtProcFilter>(),
       handler]() mutable -> ArenaPromise<absl::Status> {
        GRPC_TRACE_LOG(ext_proc_filter, INFO)
            << "ExtProc: InterceptCall promise chain start";
        auto transport = self->channel()->GetTransport();
        if (!transport.ok()) {
          return ArenaPromise<absl::Status>(
              [status = transport.status()]() -> Poll<absl::Status> {
                return status;
              });
        }
        auto ext_proc_call =
            MakeRefCounted<ExtProcCall>(std::move(*transport), self->config());
        return ArenaPromise<absl::Status>(If(
            !self->config()
                 ->processing_mode.value_or(ProcessingMode())
                 .send_request_headers,
            [self, handler, ext_proc_call]() mutable {
              return self->ClientToServerCallNonProcessingMode(
                  handler, std::move(ext_proc_call));
            },
            [self, handler, ext_proc_call]() mutable {
              return If(
                  self->config()->observability_mode,
                  [self, handler, ext_proc_call]() mutable {
                    return self->ClientToServerObservabilityMode(
                        handler, std::move(ext_proc_call));
                  },
                  [self, handler, ext_proc_call]() mutable {
                    return self->ClientToServerCallNormalMode(
                        handler, std::move(ext_proc_call));
                  });
            }));
      });
}

}  // namespace grpc_core
