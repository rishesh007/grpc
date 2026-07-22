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

#ifndef GRPC_SRC_CORE_XDS_XDS_CLIENT_SERIALIZED_STREAMING_CALL_H
#define GRPC_SRC_CORE_XDS_XDS_CLIENT_SERIALIZED_STREAMING_CALL_H

#include <grpc/support/port_platform.h>

#include <atomic>
#include <memory>
#include <string>
#include <vector>

#include "src/core/lib/promise/activity.h"
#include "src/core/lib/promise/poll.h"
#include "src/core/util/dual_ref_counted.h"
#include "src/core/util/orphanable.h"
#include "src/core/xds/xds_client/xds_transport.h"
#include "absl/functional/any_invocable.h"
#include "absl/status/status.h"

namespace grpc_core {

class StreamingCallPromiseWrapper final
    : public DualRefCounted<StreamingCallPromiseWrapper> {
 public:
  using XdsTransport = XdsTransportFactory::XdsTransport;

  StreamingCallPromiseWrapper(
      XdsTransport& transport, const char* method,
      std::unique_ptr<
          XdsTransportFactory::XdsTransport::StreamingCall::EventHandler>
          event_handler = nullptr,
      bool wait_for_ready = true);

  ~StreamingCallPromiseWrapper() override = default;

  void Orphaned() override;

  // Returns a promise that does not resolve until the send is complete.
  absl::AnyInvocable<Poll<absl::Status>()> Send(std::string msg);

  void StartRecvMessage();
  void SendHalfClose();

 private:
  class EventHandler;

  OrphanablePtr<XdsTransportFactory::XdsTransport::StreamingCall> call_;
  std::atomic<bool> send_message_in_flight_{false};
  std::atomic<bool> half_close_pending_{false};
  std::atomic<bool> send_failed_{false};
  std::vector<Waker> send_message_wakers_;
};

}  // namespace grpc_core

#endif  // GRPC_SRC_CORE_XDS_XDS_CLIENT_SERIALIZED_STREAMING_CALL_H
