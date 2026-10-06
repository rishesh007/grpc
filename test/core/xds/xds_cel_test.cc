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

#include <cstdint>
#include <map>
#include <memory>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include "cel-c/activation.h"
#include "cel-c/string_view_absl.h"
#include "cel-c/value.h"
#include "cel/expr/checked.upb.h"
#include "cel/expr/syntax.upb.h"
#include "upb/mem/arena.hpp"
#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/status/status.h"
#include "absl/strings/string_view.h"

namespace grpc_core {
namespace testing {
namespace {

// Variable resolver backed by a map of names to values.
class MapResolver : public cel_VariableResolver {
 public:
  MapResolver() { vtable = &kVTable; }

  void SetBool(absl::string_view name, bool value) {
    cel_Value v;
    cel_Value_SetBool(&v, value);
    bindings_[std::string(name)] = v;
  }

  void SetString(absl::string_view name, absl::string_view value) {
    strings_.push_back(std::make_unique<std::string>(value));
    cel_Value v;
    cel_Value_SetString(&v, cel_StringView_FromAbsl(*strings_.back()));
    bindings_[std::string(name)] = v;
  }

 private:
  static cel_Trilean Find(const cel_VariableResolver* resolver,
                          cel_StringView name, cel_Value* value,
                          cel_Arena* /*arena*/, cel_Status* /*status*/) {
    const auto* self = static_cast<const MapResolver*>(resolver);
    auto it = self->bindings_.find(std::string(cel_StringView_ToAbsl(name)));
    if (it == self->bindings_.end()) return cel_Trilean_kFalse;
    *value = it->second;
    return cel_Trilean_kTrue;
  }

  static constexpr cel_VariableResolverVTable kVTable = {&Find};

  std::map<std::string, cel_Value> bindings_;
  std::vector<std::unique_ptr<std::string>> strings_;
};

// Helpers for building CheckedExpr protos by hand.
class CelProgramTest : public ::testing::Test {
 protected:
  cel_expr_CheckedExpr* NewCheckedExpr(cel_expr_Expr** root) {
    cel_expr_CheckedExpr* checked = cel_expr_CheckedExpr_new(arena_.ptr());
    *root = cel_expr_CheckedExpr_mutable_expr(checked, arena_.ptr());
    cel_expr_Expr_set_id(*root, next_id_++);
    return checked;
  }

  void SetBoolConst(cel_expr_Expr* expr, bool value) {
    cel_expr_Constant_set_bool_value(
        cel_expr_Expr_mutable_const_expr(expr, arena_.ptr()), value);
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

  // Makes expr a call to function, returning the arg exprs.
  std::vector<cel_expr_Expr*> SetCall(cel_expr_Expr* expr,
                                      absl::string_view function,
                                      int num_args) {
    cel_expr_Expr_Call* call =
        cel_expr_Expr_mutable_call_expr(expr, arena_.ptr());
    cel_expr_Expr_Call_set_function(call, cel_StringView_FromAbsl(function));
    std::vector<cel_expr_Expr*> args;
    for (int i = 0; i < num_args; ++i) {
      cel_expr_Expr* arg = cel_expr_Expr_Call_add_args(call, arena_.ptr());
      cel_expr_Expr_set_id(arg, next_id_++);
      args.push_back(arg);
    }
    return args;
  }

  std::unique_ptr<CelProgram> Compile(const cel_expr_CheckedExpr* checked) {
    auto program = CelProgram::Create(checked);
    EXPECT_TRUE(program.ok()) << program.status();
    return program.ok() ? std::move(*program) : nullptr;
  }

  upb::Arena arena_;
  int64_t next_id_ = 1;
  MapResolver resolver_;
};

TEST_F(CelProgramTest, NullExpression) {
  auto program = CelProgram::Create(nullptr);
  EXPECT_EQ(program.status().code(), absl::StatusCode::kInvalidArgument);
}

TEST_F(CelProgramTest, BoolConstant) {
  cel_expr_Expr* root;
  auto* checked = NewCheckedExpr(&root);
  SetBoolConst(root, true);
  auto program = Compile(checked);
  ASSERT_NE(program, nullptr);
  EXPECT_EQ(program->EvaluateBool(resolver_), true);
  // Wrong result type.
  EXPECT_EQ(program->EvaluateString(resolver_), std::nullopt);
}

TEST_F(CelProgramTest, StringConstant) {
  cel_expr_Expr* root;
  auto* checked = NewCheckedExpr(&root);
  SetStringConst(root, "foo");
  auto program = Compile(checked);
  ASSERT_NE(program, nullptr);
  EXPECT_EQ(program->EvaluateString(resolver_), "foo");
  // Wrong result type.
  EXPECT_EQ(program->EvaluateBool(resolver_), std::nullopt);
}

TEST_F(CelProgramTest, IdentResolvedFromResolver) {
  cel_expr_Expr* root;
  auto* checked = NewCheckedExpr(&root);
  SetIdent(root, "x");
  auto program = Compile(checked);
  ASSERT_NE(program, nullptr);
  resolver_.SetBool("x", true);
  EXPECT_EQ(program->EvaluateBool(resolver_), true);
  resolver_.SetBool("x", false);
  EXPECT_EQ(program->EvaluateBool(resolver_), false);
  resolver_.SetString("x", "bar");
  EXPECT_EQ(program->EvaluateString(resolver_), "bar");
}

TEST_F(CelProgramTest, UnresolvedIdentFailsEvaluation) {
  cel_expr_Expr* root;
  auto* checked = NewCheckedExpr(&root);
  SetIdent(root, "missing");
  auto program = Compile(checked);
  ASSERT_NE(program, nullptr);
  EXPECT_EQ(program->EvaluateBool(resolver_), std::nullopt);
}

TEST_F(CelProgramTest, StringEquality) {
  cel_expr_Expr* root;
  auto* checked = NewCheckedExpr(&root);
  auto args = SetCall(root, "_==_", 2);
  SetIdent(args[0], "x");
  SetStringConst(args[1], "bar");
  auto program = Compile(checked);
  ASSERT_NE(program, nullptr);
  resolver_.SetString("x", "bar");
  EXPECT_EQ(program->EvaluateBool(resolver_), true);
  resolver_.SetString("x", "baz");
  EXPECT_EQ(program->EvaluateBool(resolver_), false);
}

TEST_F(CelProgramTest, StartsWith) {
  cel_expr_Expr* root;
  auto* checked = NewCheckedExpr(&root);
  // Receiver-style call: x.startsWith("ba").
  cel_expr_Expr_Call* call =
      cel_expr_Expr_mutable_call_expr(root, arena_.ptr());
  cel_expr_Expr_Call_set_function(call, cel_StringView_FromAbsl("startsWith"));
  cel_expr_Expr* target = cel_expr_Expr_Call_mutable_target(call, arena_.ptr());
  cel_expr_Expr_set_id(target, next_id_++);
  SetIdent(target, "x");
  cel_expr_Expr* arg = cel_expr_Expr_Call_add_args(call, arena_.ptr());
  cel_expr_Expr_set_id(arg, next_id_++);
  SetStringConst(arg, "ba");
  auto program = Compile(checked);
  ASSERT_NE(program, nullptr);
  resolver_.SetString("x", "bar");
  EXPECT_EQ(program->EvaluateBool(resolver_), true);
  resolver_.SetString("x", "foo");
  EXPECT_EQ(program->EvaluateBool(resolver_), false);
}

TEST_F(CelProgramTest, Equality) {
  cel_expr_Expr* root1;
  auto* checked1 = NewCheckedExpr(&root1);
  SetStringConst(root1, "foo");
  cel_expr_Expr* root2;
  auto* checked2 = NewCheckedExpr(&root2);
  SetStringConst(root2, "bar");
  auto program1 = Compile(checked1);
  auto program1_copy = Compile(checked1);
  auto program2 = Compile(checked2);
  ASSERT_NE(program1, nullptr);
  ASSERT_NE(program1_copy, nullptr);
  ASSERT_NE(program2, nullptr);
  EXPECT_EQ(*program1, *program1_copy);
  EXPECT_NE(*program1, *program2);
}

}  // namespace
}  // namespace testing
}  // namespace grpc_core

int main(int argc, char** argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
