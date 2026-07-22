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

#include "src/core/xds/xds_client/serialized_streaming_call.h"

#include <grpc/support/port_platform.h>

#include <memory>
#include <optional>
#include <string>
#include <utility>

#include "src/core/lib/promise/activity.h"
#include "src/core/lib/promise/poll.h"
#include "absl/functional/any_invocable.h"
#include "absl/status/status.h"
#include "absl/strings/string_view.h"

namespace grpc_core {

class StreamingCallPromiseWrapper::EventHandler final
    : public XdsTransportFactory::XdsTransport::StreamingCall::EventHandler {
 public:
  explicit EventHandler(
      WeakRefCountedPtr<StreamingCallPromiseWrapper> promise_wrapper,
      std::unique_ptr<
          XdsTransportFactory::XdsTransport::StreamingCall::EventHandler>
          user_event_handler)
      : promise_wrapper_(std::move(promise_wrapper)),
        user_event_handler_(std::move(user_event_handler)) {}

  void OnRequestSent(bool ok) override {
    if (promise_wrapper_ != nullptr) {
      if (!ok) {
        promise_wrapper_->send_failed_.store(true);
      }
      promise_wrapper_->send_message_in_flight_.store(false);
      auto wakeups = std::move(promise_wrapper_->send_message_wakers_);
      for (auto& waker : wakeups) {
        waker.Wakeup();
      }
      if (promise_wrapper_->half_close_pending_.exchange(false) &&
          promise_wrapper_->call_ != nullptr) {
        promise_wrapper_->call_->SendHalfClose();
      }
    }
    if (user_event_handler_ != nullptr) {
      user_event_handler_->OnRequestSent(ok);
    }
  }

  void OnRecvMessage(absl::string_view payload) override {
    if (user_event_handler_ != nullptr) {
      user_event_handler_->OnRecvMessage(payload);
    }
  }

  void OnStatusReceived(absl::Status status) override {
    if (promise_wrapper_ != nullptr) {
      if (!status.ok()) {
        promise_wrapper_->send_failed_.store(true);
      }
      promise_wrapper_->send_message_in_flight_.store(false);
      auto wakeups = std::move(promise_wrapper_->send_message_wakers_);
      for (auto& waker : wakeups) {
        waker.Wakeup();
      }
    }
    if (user_event_handler_ != nullptr) {
      user_event_handler_->OnStatusReceived(std::move(status));
    }
  }

 private:
  WeakRefCountedPtr<StreamingCallPromiseWrapper> promise_wrapper_;
  std::unique_ptr<
      XdsTransportFactory::XdsTransport::StreamingCall::EventHandler>
      user_event_handler_;
};

StreamingCallPromiseWrapper::StreamingCallPromiseWrapper(
    XdsTransport& transport, const char* method,
    std::unique_ptr<
        XdsTransportFactory::XdsTransport::StreamingCall::EventHandler>
        event_handler,
    bool wait_for_ready) {
  auto internal_event_handler = std::make_unique<EventHandler>(
      WeakRefAsSubclass<StreamingCallPromiseWrapper>(),
      std::move(event_handler));
  call_ = transport.CreateStreamingCall(
      method, std::move(internal_event_handler), wait_for_ready);
}

absl::AnyInvocable<Poll<absl::Status>()> StreamingCallPromiseWrapper::Send(
    std::string msg) {
  return [self = WeakRefAsSubclass<StreamingCallPromiseWrapper>(),
          msg = std::make_optional(
              std::move(msg))]() mutable -> Poll<absl::Status> {
    if (self == nullptr) {
      return absl::CancelledError("Stream closed");
    }
    if (self->send_failed_.load()) {
      return absl::InternalError("Send failed");
    }
    // If we've not yet started the send op, try to do so.
    if (msg.has_value()) {
      bool send_message_in_flight = false;
      if (!self->send_message_in_flight_.compare_exchange_strong(
              send_message_in_flight, true)) {
        self->send_message_wakers_.push_back(
            GetContext<Activity>()->MakeNonOwningWaker());
        return Pending{};
      }
      self->call_->SendMessage(std::move(*msg));
      msg.reset();
    }
    // Already started. Check to see if it's still in flight.
    if (self->send_message_in_flight_.load()) {
      self->send_message_wakers_.push_back(
          GetContext<Activity>()->MakeNonOwningWaker());
      return Pending{};
    }
    if (self->send_failed_.load()) {
      return absl::InternalError("Send failed");
    }
    return absl::OkStatus();
  };
}

void StreamingCallPromiseWrapper::StartRecvMessage() {
  call_->StartRecvMessage();
}

void StreamingCallPromiseWrapper::SendHalfClose() {
  if (send_message_in_flight_.load()) {
    half_close_pending_.store(true);
  } else {
    call_->SendHalfClose();
  }
}

void StreamingCallPromiseWrapper::Orphaned() {
  send_failed_.store(true);
  send_message_in_flight_.store(false);
  auto wakeups = std::move(send_message_wakers_);
  for (auto& waker : wakeups) {
    waker.Wakeup();
  }
  call_.reset();
}

}  // namespace grpc_core
