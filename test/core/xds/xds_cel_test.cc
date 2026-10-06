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

using ResultType = CelProgram::ResultType;

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
  // Creates a CheckedExpr whose result has the given type.
  cel_expr_CheckedExpr* NewCheckedExpr(cel_expr_Expr** root,
                                       int32_t result_type) {
    cel_expr_CheckedExpr* checked = NewCheckedExpr(root);
    cel_expr_Type* type = cel_expr_Type_new(arena_.ptr());
    cel_expr_Type_set_primitive(type, result_type);
    cel_expr_CheckedExpr_type_map_set(checked, cel_expr_Expr_id(*root), type,
                                      arena_.ptr());
    return checked;
  }

  // Creates a CheckedExpr with no result type.
  cel_expr_CheckedExpr* NewCheckedExpr(cel_expr_Expr** root) {
    cel_expr_CheckedExpr* checked = cel_expr_CheckedExpr_new(arena_.ptr());
    *root = NewExpr(cel_expr_CheckedExpr_mutable_expr(checked, arena_.ptr()));
    return checked;
  }

  cel_expr_Expr* NewExpr(cel_expr_Expr* expr) {
    cel_expr_Expr_set_id(expr, next_id_++);
    return expr;
  }

  void SetBoolConst(cel_expr_Expr* expr, bool value) {
    cel_expr_Constant_set_bool_value(
        cel_expr_Expr_mutable_const_expr(expr, arena_.ptr()), value);
  }

  void SetIntConst(cel_expr_Expr* expr, int64_t value) {
    cel_expr_Constant_set_int64_value(
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

  // Makes expr a receiver-style call target.function(arg), returning
  // {target, arg}.
  std::pair<cel_expr_Expr*, cel_expr_Expr*> SetReceiverCall(
      cel_expr_Expr* expr, absl::string_view function) {
    cel_expr_Expr_Call* call =
        cel_expr_Expr_mutable_call_expr(expr, arena_.ptr());
    cel_expr_Expr_Call_set_function(call, cel_StringView_FromAbsl(function));
    cel_expr_Expr* target =
        NewExpr(cel_expr_Expr_Call_mutable_target(call, arena_.ptr()));
    cel_expr_Expr* arg =
        NewExpr(cel_expr_Expr_Call_add_args(call, arena_.ptr()));
    return {target, arg};
  }

  // Records the type-checker's overload resolution for expr.
  void SetOverload(cel_expr_CheckedExpr* checked, cel_expr_Expr* expr,
                   absl::string_view overload_id) {
    cel_expr_Reference* reference = cel_expr_Reference_new(arena_.ptr());
    cel_expr_Reference_add_overload_id(
        reference, cel_StringView_FromAbsl(overload_id), arena_.ptr());
    cel_expr_CheckedExpr_reference_map_set(checked, cel_expr_Expr_id(expr),
                                           reference, arena_.ptr());
  }

  // Builds `request.matches(pattern)`.
  cel_expr_CheckedExpr* NewMatchesExpr(absl::string_view pattern) {
    cel_expr_Expr* root;
    auto* checked = NewCheckedExpr(&root, cel_expr_Type_BOOL);
    auto [target, arg] = SetReceiverCall(root, "matches");
    SetIdent(target, "request");
    SetStringConst(arg, pattern);
    return checked;
  }

  // Builds `1 + 2 == 3`, recording overload_id for the +, or no overload if
  // empty.
  cel_expr_CheckedExpr* NewAddExpr(absl::string_view overload_id) {
    cel_expr_Expr* root;
    auto* checked = NewCheckedExpr(&root, cel_expr_Type_BOOL);
    auto eq_args = SetCall(root, "_==_", 2);
    auto add_args = SetCall(eq_args[0], "_+_", 2);
    SetIntConst(add_args[0], 1);
    SetIntConst(add_args[1], 2);
    SetIntConst(eq_args[1], 3);
    if (!overload_id.empty()) SetOverload(checked, eq_args[0], overload_id);
    return checked;
  }

  std::unique_ptr<CelProgram> Compile(const cel_expr_CheckedExpr* checked,
                                      ResultType result_type) {
    auto program = CelProgram::Create(checked, result_type);
    EXPECT_TRUE(program.ok()) << program.status();
    return program.ok() ? std::move(*program) : nullptr;
  }

  void ExpectInvalid(const cel_expr_CheckedExpr* checked,
                     ResultType result_type, absl::string_view message) {
    auto program = CelProgram::Create(checked, result_type);
    EXPECT_EQ(program.status().code(), absl::StatusCode::kInvalidArgument)
        << program.status();
    EXPECT_THAT(program.status().message(), ::testing::HasSubstr(message));
  }

  upb::Arena arena_;
  int64_t next_id_ = 1;
  MapResolver resolver_;
};

//
// Compilation and evaluation
//

TEST_F(CelProgramTest, BoolConstant) {
  cel_expr_Expr* root;
  auto* checked = NewCheckedExpr(&root, cel_expr_Type_BOOL);
  SetBoolConst(root, true);
  auto program = Compile(checked, ResultType::kBool);
  ASSERT_NE(program, nullptr);
  EXPECT_EQ(program->EvaluateBool(resolver_), true);
  // Wrong result type.
  EXPECT_EQ(program->EvaluateString(resolver_), std::nullopt);
}

TEST_F(CelProgramTest, StringConstant) {
  cel_expr_Expr* root;
  auto* checked = NewCheckedExpr(&root, cel_expr_Type_STRING);
  SetStringConst(root, "foo");
  auto program = Compile(checked, ResultType::kString);
  ASSERT_NE(program, nullptr);
  EXPECT_EQ(program->EvaluateString(resolver_), "foo");
  // Wrong result type.
  EXPECT_EQ(program->EvaluateBool(resolver_), std::nullopt);
}

TEST_F(CelProgramTest, IdentResolvedFromResolver) {
  cel_expr_Expr* root;
  auto* checked = NewCheckedExpr(&root, cel_expr_Type_BOOL);
  SetIdent(root, "request");
  auto program = Compile(checked, ResultType::kBool);
  ASSERT_NE(program, nullptr);
  resolver_.SetBool("request", true);
  EXPECT_EQ(program->EvaluateBool(resolver_), true);
  resolver_.SetBool("request", false);
  EXPECT_EQ(program->EvaluateBool(resolver_), false);
}

TEST_F(CelProgramTest, UnresolvedIdentFailsEvaluation) {
  cel_expr_Expr* root;
  auto* checked = NewCheckedExpr(&root, cel_expr_Type_BOOL);
  SetIdent(root, "request");
  auto program = Compile(checked, ResultType::kBool);
  ASSERT_NE(program, nullptr);
  EXPECT_EQ(program->EvaluateBool(resolver_), std::nullopt);
}

TEST_F(CelProgramTest, StringEquality) {
  cel_expr_Expr* root;
  auto* checked = NewCheckedExpr(&root, cel_expr_Type_BOOL);
  auto args = SetCall(root, "_==_", 2);
  SetIdent(args[0], "request");
  SetStringConst(args[1], "bar");
  auto program = Compile(checked, ResultType::kBool);
  ASSERT_NE(program, nullptr);
  resolver_.SetString("request", "bar");
  EXPECT_EQ(program->EvaluateBool(resolver_), true);
  resolver_.SetString("request", "baz");
  EXPECT_EQ(program->EvaluateBool(resolver_), false);
}

TEST_F(CelProgramTest, StartsWith) {
  cel_expr_Expr* root;
  auto* checked = NewCheckedExpr(&root, cel_expr_Type_BOOL);
  auto [target, arg] = SetReceiverCall(root, "startsWith");
  SetIdent(target, "request");
  SetStringConst(arg, "ba");
  auto program = Compile(checked, ResultType::kBool);
  ASSERT_NE(program, nullptr);
  resolver_.SetString("request", "bar");
  EXPECT_EQ(program->EvaluateBool(resolver_), true);
  resolver_.SetString("request", "foo");
  EXPECT_EQ(program->EvaluateBool(resolver_), false);
}

TEST_F(CelProgramTest, Matches) {
  auto program = Compile(NewMatchesExpr("^ba+r$"), ResultType::kBool);
  ASSERT_NE(program, nullptr);
  resolver_.SetString("request", "baaar");
  EXPECT_EQ(program->EvaluateBool(resolver_), true);
  resolver_.SetString("request", "foo");
  EXPECT_EQ(program->EvaluateBool(resolver_), false);
}

TEST_F(CelProgramTest, IntAddition) {
  auto program = Compile(NewAddExpr("add_int64"), ResultType::kBool);
  ASSERT_NE(program, nullptr);
  EXPECT_EQ(program->EvaluateBool(resolver_), true);
}

TEST_F(CelProgramTest, Equality) {
  cel_expr_Expr* root1;
  auto* checked1 = NewCheckedExpr(&root1, cel_expr_Type_STRING);
  SetStringConst(root1, "foo");
  cel_expr_Expr* root2;
  auto* checked2 = NewCheckedExpr(&root2, cel_expr_Type_STRING);
  SetStringConst(root2, "bar");
  auto program1 = Compile(checked1, ResultType::kString);
  auto program1_copy = Compile(checked1, ResultType::kString);
  auto program2 = Compile(checked2, ResultType::kString);
  ASSERT_NE(program1, nullptr);
  ASSERT_NE(program1_copy, nullptr);
  ASSERT_NE(program2, nullptr);
  EXPECT_EQ(*program1, *program1_copy);
  EXPECT_NE(*program1, *program2);
}

//
// Validation
//

TEST_F(CelProgramTest, NullExpression) {
  ExpectInvalid(nullptr, ResultType::kBool, "CEL expression not set");
}

TEST_F(CelProgramTest, EmptyExpression) {
  ExpectInvalid(cel_expr_CheckedExpr_new(arena_.ptr()), ResultType::kBool,
                "CEL expression not set");
}

TEST_F(CelProgramTest, MissingResultType) {
  cel_expr_Expr* root;
  auto* checked = NewCheckedExpr(&root);
  SetBoolConst(root, true);
  ExpectInvalid(checked, ResultType::kBool, "no type for its result");
}

TEST_F(CelProgramTest, WrongResultType) {
  cel_expr_Expr* root;
  auto* checked = NewCheckedExpr(&root, cel_expr_Type_STRING);
  SetStringConst(root, "foo");
  ExpectInvalid(checked, ResultType::kBool, "must evaluate to bool");
  cel_expr_Expr* root2;
  auto* checked2 = NewCheckedExpr(&root2, cel_expr_Type_BOOL);
  SetBoolConst(root2, true);
  ExpectInvalid(checked2, ResultType::kString, "must evaluate to string");
}

TEST_F(CelProgramTest, UnsupportedVariable) {
  cel_expr_Expr* root;
  auto* checked = NewCheckedExpr(&root, cel_expr_Type_BOOL);
  auto args = SetCall(root, "_==_", 2);
  SetIdent(args[0], "response");
  SetStringConst(args[1], "foo");
  ExpectInvalid(checked, ResultType::kBool,
                "CEL variable \"response\" is not supported");
}

TEST_F(CelProgramTest, Comprehension) {
  cel_expr_Expr* root;
  auto* checked = NewCheckedExpr(&root, cel_expr_Type_BOOL);
  cel_expr_Expr_mutable_comprehension_expr(root, arena_.ptr());
  ExpectInvalid(checked, ResultType::kBool, "comprehensions");
}

TEST_F(CelProgramTest, NestedComprehension) {
  cel_expr_Expr* root;
  auto* checked = NewCheckedExpr(&root, cel_expr_Type_BOOL);
  auto args = SetCall(root, "_&&_", 2);
  SetBoolConst(args[0], true);
  cel_expr_Expr* list = cel_expr_Expr_CreateList_add_elements(
      cel_expr_Expr_mutable_list_expr(args[1], arena_.ptr()), arena_.ptr());
  cel_expr_Expr_mutable_comprehension_expr(NewExpr(list), arena_.ptr());
  ExpectInvalid(checked, ResultType::kBool, "comprehensions");
}

TEST_F(CelProgramTest, StringConversion) {
  cel_expr_Expr* root;
  auto* checked = NewCheckedExpr(&root, cel_expr_Type_STRING);
  SetIdent(SetCall(root, "string", 1)[0], "request");
  ExpectInvalid(checked, ResultType::kString, "string() conversions");
}

TEST_F(CelProgramTest, StringConcatenation) {
  ExpectInvalid(NewAddExpr("add_string"), ResultType::kBool, "concatenation");
}

TEST_F(CelProgramTest, ListConcatenation) {
  ExpectInvalid(NewAddExpr("add_list"), ResultType::kBool, "concatenation");
}

TEST_F(CelProgramTest, AdditionWithoutOverload) {
  ExpectInvalid(NewAddExpr(""), ResultType::kBool, "no overload for +");
}

TEST_F(CelProgramTest, NonConstantRegex) {
  cel_expr_Expr* root;
  auto* checked = NewCheckedExpr(&root, cel_expr_Type_BOOL);
  // Global-style matches(request, request).
  auto args = SetCall(root, "matches", 2);
  SetIdent(args[0], "request");
  SetIdent(args[1], "request");
  ExpectInvalid(checked, ResultType::kBool, "must be a constant string");
}

TEST_F(CelProgramTest, InvalidRegex) {
  ExpectInvalid(NewMatchesExpr("(unclosed"), ResultType::kBool,
                "pattern is invalid");
}

TEST_F(CelProgramTest, RegexTooLarge) {
  ExpectInvalid(NewMatchesExpr("a{200}"), ResultType::kBool,
                "exceeds the limit of 100");
}

}  // namespace
}  // namespace testing
}  // namespace grpc_core

int main(int argc, char** argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
