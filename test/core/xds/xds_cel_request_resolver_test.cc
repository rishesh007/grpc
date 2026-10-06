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

#include "src/core/xds/grpc/xds_cel_request_resolver.h"

#include <cstdint>
#include <map>
#include <memory>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include "cel-c/activation.h"
#include "cel-c/alloc.h"
#include "cel-c/arena.h"
#include "cel-c/status.h"
#include "cel-c/string_view_absl.h"
#include "cel-c/value.h"
#include "cel/expr/checked.upb.h"
#include "cel/expr/syntax.upb.h"
#include "src/core/call/metadata_batch.h"
#include "src/core/lib/slice/slice.h"
#include "src/core/xds/grpc/xds_cel.h"
#include "src/core/xds/grpc/xds_matcher_context.h"
#include "upb/mem/arena.hpp"
#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/strings/string_view.h"

namespace grpc_core {
namespace testing {
namespace {

using ResultType = CelProgram::ResultType;

class CelRequestResolverTest : public ::testing::Test {
 protected:
  CelRequestResolverTest() {
    metadata_.Set(HttpPathMetadata(),
                  Slice::FromStaticString("/package.Service/Method"));
    metadata_.Set(HttpAuthorityMetadata(),
                  Slice::FromStaticString("server.example.com"));
    Append("x-foo", "bar");
    Append("user-agent", "test-agent");
    Append("x-data-bin", "binary");
  }

  void Append(absl::string_view key, absl::string_view value) {
    metadata_.Append(key, Slice::FromCopiedString(value),
                     [&](absl::string_view error, const Slice&) {
                       FAIL() << "failed to append " << key << ": " << error;
                     });
  }

  // Helpers for building CheckedExpr protos by hand.
  cel_expr_Expr* NewExpr(cel_expr_Expr* expr) {
    cel_expr_Expr_set_id(expr, next_id_++);
    return expr;
  }

  // Creates a CheckedExpr whose result has the given type.
  cel_expr_CheckedExpr* NewCheckedExpr(cel_expr_Expr** root,
                                       ResultType result_type) {
    cel_expr_CheckedExpr* checked = cel_expr_CheckedExpr_new(arena_.ptr());
    *root = NewExpr(cel_expr_CheckedExpr_mutable_expr(checked, arena_.ptr()));
    cel_expr_Type* type = cel_expr_Type_new(arena_.ptr());
    cel_expr_Type_set_primitive(type, result_type == ResultType::kBool
                                          ? cel_expr_Type_BOOL
                                          : cel_expr_Type_STRING);
    cel_expr_CheckedExpr_type_map_set(checked, cel_expr_Expr_id(*root), type,
                                      arena_.ptr());
    return checked;
  }

  void SetStringConst(cel_expr_Expr* expr, absl::string_view value) {
    cel_expr_Constant_set_string_value(
        cel_expr_Expr_mutable_const_expr(expr, arena_.ptr()),
        cel_StringView_FromAbsl(value));
  }

  void SetIdent(cel_expr_Expr* expr, absl::string_view name) {
    cel_expr_Expr_Ident_set_name(
        cel_expr_Expr_mutable_ident_expr(expr, arena_.ptr()),
        cel_StringView_FromAbsl(name));
  }

  // Makes expr `operand.field` (or `has(operand.field)` if test_only),
  // returning the operand expr.
  cel_expr_Expr* SetSelect(cel_expr_Expr* expr, absl::string_view field,
                           bool test_only = false) {
    cel_expr_Expr_Select* select =
        cel_expr_Expr_mutable_select_expr(expr, arena_.ptr());
    cel_expr_Expr_Select_set_field(select, cel_StringView_FromAbsl(field));
    cel_expr_Expr_Select_set_test_only(select, test_only);
    return NewExpr(cel_expr_Expr_Select_mutable_operand(select, arena_.ptr()));
  }

  // Makes expr `request.<field>`.
  void SetRequestField(cel_expr_Expr* expr, absl::string_view field,
                       bool test_only = false) {
    SetIdent(SetSelect(expr, field, test_only), "request");
  }

  // Makes expr a global call to function, returning the arg exprs.
  std::vector<cel_expr_Expr*> SetCall(cel_expr_Expr* expr,
                                      absl::string_view function,
                                      int num_args) {
    cel_expr_Expr_Call* call =
        cel_expr_Expr_mutable_call_expr(expr, arena_.ptr());
    cel_expr_Expr_Call_set_function(call, cel_StringView_FromAbsl(function));
    std::vector<cel_expr_Expr*> args;
    for (int i = 0; i < num_args; ++i) {
      args.push_back(NewExpr(cel_expr_Expr_Call_add_args(call, arena_.ptr())));
    }
    return args;
  }

  std::unique_ptr<CelProgram> Compile(const cel_expr_CheckedExpr* checked,
                                      ResultType result_type) {
    auto program = CelProgram::Create(checked, result_type);
    EXPECT_TRUE(program.ok()) << program.status();
    return program.ok() ? std::move(*program) : nullptr;
  }

  // Compiles `request.<field>` and evaluates it as a string.
  std::optional<std::string> EvaluateRequestField(absl::string_view field) {
    cel_expr_Expr* root;
    auto* checked = NewCheckedExpr(&root, ResultType::kString);
    SetRequestField(root, field);
    auto program = Compile(checked, ResultType::kString);
    if (program == nullptr) return std::nullopt;
    return program->EvaluateString(resolver_);
  }

  // Compiles `has(request.<field>)` and evaluates it.
  std::optional<bool> EvaluateHasRequestField(absl::string_view field) {
    cel_expr_Expr* root;
    auto* checked = NewCheckedExpr(&root, ResultType::kBool);
    SetRequestField(root, field, /*test_only=*/true);
    auto program = Compile(checked, ResultType::kBool);
    if (program == nullptr) return std::nullopt;
    return program->EvaluateBool(resolver_);
  }

  // Compiles `request.headers[key]` and evaluates it as a string.
  std::optional<std::string> EvaluateHeader(absl::string_view key) {
    cel_expr_Expr* root;
    auto* checked = NewCheckedExpr(&root, ResultType::kString);
    auto args = SetCall(root, "_[_]", 2);
    SetRequestField(args[0], "headers");
    SetStringConst(args[1], key);
    auto program = Compile(checked, ResultType::kString);
    if (program == nullptr) return std::nullopt;
    return program->EvaluateString(resolver_);
  }

  // Compiles `key in request.headers` and evaluates it.
  std::optional<bool> EvaluateInHeaders(absl::string_view key) {
    cel_expr_Expr* root;
    auto* checked = NewCheckedExpr(&root, ResultType::kBool);
    auto args = SetCall(root, "@in", 2);
    SetStringConst(args[0], key);
    SetRequestField(args[1], "headers");
    auto program = Compile(checked, ResultType::kBool);
    if (program == nullptr) return std::nullopt;
    return program->EvaluateBool(resolver_);
  }

  upb::Arena arena_;
  int64_t next_id_ = 1;
  grpc_metadata_batch metadata_;
  RpcMatchContext context_{&metadata_};
  CelRequestResolver resolver_{context_};
};

TEST_F(CelRequestResolverTest, PathAndHost) {
  EXPECT_EQ(EvaluateRequestField("path"), "/package.Service/Method");
  EXPECT_EQ(EvaluateRequestField("url_path"), "/package.Service/Method");
  EXPECT_EQ(EvaluateRequestField("host"), "server.example.com");
}

TEST_F(CelRequestResolverTest, Constants) {
  EXPECT_EQ(EvaluateRequestField("method"), "POST");
  EXPECT_EQ(EvaluateRequestField("query"), "");
}

TEST_F(CelRequestResolverTest, HeaderBackedAttributes) {
  EXPECT_EQ(EvaluateRequestField("useragent"), "test-agent");
  EXPECT_EQ(EvaluateHasRequestField("useragent"), true);
  // Absent headers.
  EXPECT_EQ(EvaluateRequestField("referer"), std::nullopt);
  EXPECT_EQ(EvaluateHasRequestField("referer"), false);
  EXPECT_EQ(EvaluateHasRequestField("id"), false);
  Append("referer", "https://example.com");
  Append("x-request-id", "1234");
  EXPECT_EQ(EvaluateRequestField("referer"), "https://example.com");
  EXPECT_EQ(EvaluateRequestField("id"), "1234");
}

TEST_F(CelRequestResolverTest, UnsupportedAttributesAreAbsent) {
  for (absl::string_view field : {"scheme", "time", "protocol", "unknown"}) {
    EXPECT_EQ(EvaluateHasRequestField(field), false) << field;
    EXPECT_EQ(EvaluateRequestField(field), std::nullopt) << field;
  }
}

TEST_F(CelRequestResolverTest, Headers) {
  EXPECT_EQ(EvaluateHeader("x-foo"), "bar");
  // Lookups are case-insensitive.
  EXPECT_EQ(EvaluateHeader("X-Foo"), "bar");
  EXPECT_EQ(EvaluateHeader("user-agent"), "test-agent");
  EXPECT_EQ(EvaluateHeader("content-type"), "application/grpc");
  // Missing and binary headers.
  EXPECT_EQ(EvaluateHeader("missing"), std::nullopt);
  EXPECT_EQ(EvaluateHeader("x-data-bin"), std::nullopt);
}

TEST_F(CelRequestResolverTest, MultipleHeaderValuesAreJoined) {
  Append("x-foo", "baz");
  EXPECT_EQ(EvaluateHeader("x-foo"), "bar,baz");
}

TEST_F(CelRequestResolverTest, InHeaders) {
  EXPECT_EQ(EvaluateInHeaders("x-foo"), true);
  EXPECT_EQ(EvaluateInHeaders("missing"), false);
  EXPECT_EQ(EvaluateInHeaders("x-data-bin"), false);
}

TEST_F(CelRequestResolverTest, MapEquality) {
  // Map equality goes through the size and iteration paths of the map.
  for (absl::string_view field : {"", "headers"}) {
    cel_expr_Expr* root;
    auto* checked = NewCheckedExpr(&root, ResultType::kBool);
    auto args = SetCall(root, "_==_", 2);
    for (cel_expr_Expr* arg : args) {
      if (field.empty()) {
        SetIdent(arg, "request");
      } else {
        SetRequestField(arg, field);
      }
    }
    auto program = Compile(checked, ResultType::kBool);
    ASSERT_NE(program, nullptr);
    EXPECT_EQ(program->EvaluateBool(resolver_), true) << field;
  }
}

// Exercises the map vtables directly, since cel-c's interpreter does not
// yet support some map operations (e.g. size() of a map).
class CelRequestMapTest : public CelRequestResolverTest {
 protected:
  CelRequestMapTest() {
    cel_Status_Construct(&status_);
    cel_arena_ = cel_Arena_New(cel_DefaultAllocator);
    context_.alloc = cel_DefaultAllocator;
    context_.arena = cel_arena_;
  }

  ~CelRequestMapTest() override {
    EXPECT_TRUE(cel_Status_Ok(&status_));
    cel_Arena_Delete(cel_arena_);
    cel_Status_Destruct(&status_);
  }

  cel_Value ResolveRequest() {
    cel_Value value;
    EXPECT_EQ(
        resolver_.vtable->Find(&resolver_, cel_StringView_FromAbsl("request"),
                               &value, cel_arena_, &status_),
        cel_Trilean_kTrue);
    EXPECT_TRUE(cel_Value_IsMap(&value));
    return value;
  }

  cel_Value ResolveHeaders() {
    cel_Value request = ResolveRequest();
    cel_MapValueKey key;
    cel_MapValueKey_SetString(&key, cel_StringView_FromAbsl("headers"));
    cel_Value headers;
    EXPECT_TRUE(cel_MapValue_Find(cel_Value_GetMap(&request), &context_, &key,
                                  &headers, &status_));
    EXPECT_TRUE(cel_Value_IsMap(&headers));
    return headers;
  }

  int64_t Size(const cel_Value& map) {
    cel_Value size;
    EXPECT_TRUE(
        cel_MapValue_Size(cel_Value_GetMap(&map), &context_, &size, &status_));
    return cel_Value_GetInt(&size);
  }

  // Returns all entries of the map.  Map values are shown as "<map>".
  std::map<std::string, std::string> Entries(const cel_Value& map) {
    std::map<std::string, std::string> entries;
    cel_MapValueIterator* iter =
        cel_MapValue_NewIterator(cel_Value_GetMap(&map), &context_, &status_);
    EXPECT_NE(iter, nullptr);
    if (iter == nullptr) return entries;
    cel_MapValueKey key;
    cel_Value value;
    while (cel_MapValueIterator_Next(iter, &context_, &key, &value, &status_)) {
      std::string key_str(
          cel_StringView_ToAbsl(cel_MapValueKey_GetString(&key)));
      entries[key_str] =
          cel_Value_IsMap(&value)
              ? "<map>"
              : std::string(cel_StringView_ToAbsl(cel_Value_GetString(&value)));
    }
    cel_MapValueIterator_Delete(iter);
    return entries;
  }

  cel_Status status_;
  cel_Arena* cel_arena_;
  cel_ValueContext context_{};
};

TEST_F(CelRequestMapTest, RequestEntries) {
  cel_Value request = ResolveRequest();
  EXPECT_EQ(Size(request), 7);
  EXPECT_THAT(
      Entries(request),
      ::testing::UnorderedElementsAre(
          ::testing::Pair("path", "/package.Service/Method"),
          ::testing::Pair("url_path", "/package.Service/Method"),
          ::testing::Pair("host", "server.example.com"),
          ::testing::Pair("useragent", "test-agent"),
          ::testing::Pair("method", "POST"), ::testing::Pair("query", ""),
          ::testing::Pair("headers", "<map>")));
}

TEST_F(CelRequestMapTest, HeaderEntries) {
  cel_Value headers = ResolveHeaders();
  std::map<std::string, std::string> entries = Entries(headers);
  EXPECT_EQ(Size(headers), static_cast<int64_t>(entries.size()));
  // Binary headers are excluded; content-type is always present.
  EXPECT_THAT(entries, ::testing::IsSupersetOf({
                           ::testing::Pair("x-foo", "bar"),
                           ::testing::Pair("user-agent", "test-agent"),
                           ::testing::Pair("content-type", "application/grpc"),
                       }));
  EXPECT_EQ(entries.count("x-data-bin"), 0);
}

TEST_F(CelRequestMapTest, OtherVariablesAreUnresolved) {
  cel_Value value;
  EXPECT_EQ(
      resolver_.vtable->Find(&resolver_, cel_StringView_FromAbsl("response"),
                             &value, cel_arena_, &status_),
      cel_Trilean_kFalse);
}

}  // namespace
}  // namespace testing
}  // namespace grpc_core

int main(int argc, char** argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
