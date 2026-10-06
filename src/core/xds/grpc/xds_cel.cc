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

#include "src/core/xds/grpc/xds_cel.h"

#include <cstddef>
#include <memory>
#include <optional>
#include <string>
#include <utility>

#include "cel-c/alloc.h"
#include "cel-c/arena.h"
#include "cel-c/ast.h"
#include "cel-c/ast_proto.h"
#include "cel-c/runtime.h"
#include "cel-c/status.h"
#include "cel-c/status_absl.h"
#include "cel-c/string_view_absl.h"
#include "cel-c/value.h"
#include "google/protobuf/any.upbdefs.h"
#include "google/protobuf/duration.upbdefs.h"
#include "google/protobuf/struct.upbdefs.h"
#include "google/protobuf/timestamp.upbdefs.h"
#include "google/protobuf/wrappers.upbdefs.h"
#include "src/core/util/no_destruct.h"
#include "upb/mem/arena.hpp"
#include "upb/reflection/def.hpp"
#include "upb/wire/encode.h"
#include "absl/functional/function_ref.h"
#include "absl/log/check.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/str_cat.h"

namespace grpc_core {

namespace {

// RAII wrapper for cel_Status (cel-c doesn't provide one).
class CelStatus {
 public:
  CelStatus() { cel_Status_Construct(&status_); }
  ~CelStatus() { cel_Status_Destruct(&status_); }
  CelStatus(const CelStatus&) = delete;
  CelStatus& operator=(const CelStatus&) = delete;

  cel_Status* get() { return &status_; }
  bool ok() const { return cel_Status_Ok(&status_); }
  absl::Status ToAbsl() const { return cel_Status_ToAbsl(&status_); }

 private:
  cel_Status status_;
};

struct ArenaDeleter {
  void operator()(cel_Arena* arena) const { cel_Arena_Delete(arena); }
};
using ArenaPtr = std::unique_ptr<cel_Arena, ArenaDeleter>;

struct AstDeleter {
  void operator()(cel_Ast* ast) const { cel_Ast_Delete(ast); }
};
using AstPtr = std::unique_ptr<cel_Ast, AstDeleter>;

struct ActivationDeleter {
  void operator()(cel_Activation* activation) const {
    cel_Activation_Delete(activation);
  }
};
using ActivationPtr = std::unique_ptr<cel_Activation, ActivationDeleter>;

// Process-wide CEL runtime, shared by all programs.  cel_Runtime is
// immutable after creation and ref-counted by the programs compiled from
// it, so it is safe to share across threads.
class SharedCelRuntime {
 public:
  SharedCelRuntime() {
    // Load the well-known types that cel-c requires into the def pool.
    // Loading any message from a file loads the whole file.
    google_protobuf_Any_getmsgdef(def_pool_.ptr());
    google_protobuf_Duration_getmsgdef(def_pool_.ptr());
    google_protobuf_Struct_getmsgdef(def_pool_.ptr());
    google_protobuf_Timestamp_getmsgdef(def_pool_.ptr());
    google_protobuf_BoolValue_getmsgdef(def_pool_.ptr());
    CelStatus status;
    runtime_ = cel_Runtime_New(cel_DefaultAllocator, def_pool_.ptr(),
                               /*opts=*/nullptr, status.get());
    CHECK(runtime_ != nullptr)
        << "failed to create CEL runtime: " << status.ToAbsl();
  }

  const cel_Runtime* runtime() const { return runtime_; }

 private:
  upb::DefPool def_pool_;
  cel_Runtime* runtime_ = nullptr;
};

const cel_Runtime* GetCelRuntime() {
  static NoDestruct<SharedCelRuntime> runtime;
  return runtime->runtime();
}

// Activates and runs program, then passes the result to on_result.
// Returns false if evaluation failed or the result is a CEL error or
// unknown.
bool Evaluate(const cel_Program* program, const cel_VariableResolver& resolver,
              absl::FunctionRef<void(const cel_Value&)> on_result) {
  ActivationPtr activation(
      cel_Program_Activate(program, &resolver, /*opts=*/nullptr));
  if (activation == nullptr) return false;
  ArenaPtr arena(cel_Arena_New(cel_DefaultAllocator));
  if (arena == nullptr) return false;
  cel_Value result;
  CelStatus status;
  if (!cel_Activation_Execute(activation.get(), &result, arena.get(),
                              status.get()) ||
      !status.ok()) {
    return false;
  }
  if (cel_Value_IsError(&result) || cel_Value_IsUnknown(&result)) return false;
  // The result may reference memory in arena, so it must be consumed
  // before arena is destroyed.
  on_result(result);
  return true;
}

}  // namespace

absl::StatusOr<std::unique_ptr<CelProgram>> CelProgram::Create(
    const cel_expr_CheckedExpr* checked_expr) {
  if (checked_expr == nullptr) {
    return absl::InvalidArgumentError("CEL expression not set");
  }
  // Serialize deterministically for use in equality comparisons.
  upb::Arena upb_arena;
  size_t size;
  const char* serialized = cel_expr_CheckedExpr_serialize_ex(
      checked_expr, kUpb_EncodeOption_Deterministic, upb_arena.ptr(), &size);
  if (serialized == nullptr) {
    return absl::InvalidArgumentError("failed to serialize CEL expression");
  }
  // Convert to a cel-c AST and compile it.  The compiled program copies
  // everything it needs, so the AST and its arena may be freed afterwards.
  ArenaPtr arena(cel_Arena_New(cel_DefaultAllocator));
  if (arena == nullptr) {
    return absl::ResourceExhaustedError("failed to allocate CEL arena");
  }
  CelStatus status;
  AstPtr ast(cel_Ast_FromProto(checked_expr, arena.get(), status.get()));
  if (ast == nullptr || !status.ok()) {
    return absl::InvalidArgumentError(absl::StrCat(
        "failed to convert CEL expression: ", status.ToAbsl().message()));
  }
  ProgramPtr program(cel_Runtime_Compile(GetCelRuntime(), ast.get(),
                                         /*opts=*/nullptr, status.get()));
  if (program == nullptr || !status.ok()) {
    return absl::InvalidArgumentError(absl::StrCat(
        "failed to compile CEL expression: ", status.ToAbsl().message()));
  }
  return std::unique_ptr<CelProgram>(
      new CelProgram(std::string(serialized, size), std::move(program)));
}

std::optional<bool> CelProgram::EvaluateBool(
    const cel_VariableResolver& resolver) const {
  std::optional<bool> result;
  if (!Evaluate(program_.get(), resolver, [&](const cel_Value& value) {
        if (cel_Value_IsBool(&value)) result = cel_Value_GetBool(&value);
      })) {
    return std::nullopt;
  }
  return result;
}

std::optional<std::string> CelProgram::EvaluateString(
    const cel_VariableResolver& resolver) const {
  std::optional<std::string> result;
  if (!Evaluate(program_.get(), resolver, [&](const cel_Value& value) {
        if (cel_Value_IsString(&value)) {
          result =
              std::string(cel_StringView_ToAbsl(cel_Value_GetString(&value)));
        }
      })) {
    return std::nullopt;
  }
  return result;
}

std::string CelProgram::ToString() const {
  return absl::StrCat("CelProgram{checked_expr_size=", serialized_expr_.size(),
                      "}");
}

}  // namespace grpc_core
