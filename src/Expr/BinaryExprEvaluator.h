// Copyright 2021-2022 Software Quality Laboratory, NYCU.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

#ifndef S2E_PLUGINS_CRAX_BINARY_EXPR_EVALUATOR_H
#define S2E_PLUGINS_CRAX_BINARY_EXPR_EVALUATOR_H

#include <s2e/Plugins/CRAX/Expr/Expr.h>

#include <string>

namespace klee {

// This is CRAX's extension to klee.
//
// Given an expression tree (where each node of the tree is either a BinaryExpr or ConstantExpr),
// evaluate it to either a constant value (uint64_t) or an infix expr (std::string).
template <typename T>
T evaluate(const ref<Expr> &e);

// Explicit (full) template specialization [with T = uint64_t].
template <>
uint64_t evaluate(const ref<Expr> &e);

// Explicit (full) template specialization [with T = std::string].
template <>
std::string evaluate(const ref<Expr> &e);

}  // namespace klee

#endif  // S2E_PLUGINS_CRAX_BINARY_EXPR_EVALUATOR_H
