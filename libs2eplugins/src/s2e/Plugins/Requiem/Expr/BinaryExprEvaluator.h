// Copyright (C) 2021-2022, Marco Wang
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

#ifndef S2E_PLUGINS_REQUIEM_BINARY_EXPR_EVALUATOR_H
#define S2E_PLUGINS_REQUIEM_BINARY_EXPR_EVALUATOR_H

#include <s2e/Plugins/Requiem/Expr/SymbolAccessExpr.h>
#include <s2e/Plugins/Requiem/Expr/BinaryExprIterator.h>

#include <stack>
#include <string>
#include <type_traits>

namespace klee {

// This is Requiem's extension to klee.
//
// Given an expression tree (where each node of the tree is either a BinaryExpr or ConstantExpr),
// evaluate it to either a constant value (uint64_t) or a std::string of infix expression.

template <typename>
inline constexpr bool always_false_v = false;


template <typename T>
class BinaryExprEvaluator {
public:
    BinaryExprEvaluator() = default;

    T evaluate(const ref<Expr> &e) const;

private:
    bool isValidOperator(const ref<Expr> &e) const {
        return dyn_cast<AddExpr>(e) ||
               dyn_cast<SubExpr>(e) ||
               dyn_cast<MulExpr>(e);
    }
};


// Implementations
template <typename T>
T BinaryExprEvaluator<T>::evaluate(const ref<Expr> &e) const {
    T ret {};

    if constexpr (std::is_same_v<uint64_t, T>) {
        std::stack<ref<Expr>> stack;

        // Evaluates an expr to an integer constant.
        for (auto it = BinaryExprIterator<IterStrategy::POST_ORDER>::begin(e);
                it != decltype(it)::end();
                it++) {
            ref<Expr> node = *it;

            if (auto sae = dyn_cast<SymbolAccessExpr>(node)) {
                // SymbolAccessExpr, essentially, is an AddExpr,
                // but during reverse polish notation evaluation
                // we should treat it like a ConstantExpr.
                stack.push(sae->sumExpr());
            } else if (auto ce = dyn_cast<ConstantExpr>(node)) {
                stack.push(ce);
            } else if (isValidOperator(node)) {
                assert(stack.size() >= 2);

                auto op2 = dyn_cast<ConstantExpr>(stack.top());
                stack.pop();
                auto op1 = dyn_cast<ConstantExpr>(stack.top());
                stack.pop();
                assert(op1 && op2);

                ref<ConstantExpr> result = nullptr;

                switch (node->getKind()) {
                    case Expr::Kind::Add:
                        result = op1->Add(op2);
                        break;
                    case Expr::Kind::Sub:
                        result = op1->Sub(op2);
                        break;
                    case Expr::Kind::Mul:
                        result = op1->Mul(op2);
                        break;
                    default:
                        break;
                }

                stack.push(result);
            }
        }

        assert(stack.size() == 1);
        auto ce = dyn_cast<ConstantExpr>(stack.top());
        ret = ce->getZExtValue();

    } else if constexpr (std::is_same_v<std::string, T>) {
        // Evaluates an expr to a string of infix expression,
        // e.g., "3 + 2", "0 + elf.sym['read'] + 0x30 * 2"
        for (auto it = BinaryExprIterator<IterStrategy::IN_ORDER>::begin(e);
             it != decltype(it)::end();
             it++) {
            ref<Expr> node = *it;

            if (auto sae = dyn_cast<SymbolAccessExpr>(node)) {
                ret += sae->toString();
            } else if (auto ce = dyn_cast<ConstantExpr>(node)) {
                std::string s;
                ce->toString(s, /*Base=*/16);
                ret += "0x" + s;
            } else {
                switch (node->getKind()) {
                    case Expr::Kind::Add:
                        ret += " + ";
                        break;
                    case Expr::Kind::Sub:
                        ret += " - ";
                        break;
                    case Expr::Kind::Mul:
                        ret += " * ";
                        break;
                    default:
                        break;
                }
            }
        }

    } else {
        // https://stackoverflow.com/questions/53945490/how-to-assert-that-a-constexpr-if-else-clause-never-happen
        static_assert(always_false_v<T>, "unsupported operation!");
    }

    return ret;
}

}  // namespace klee

#endif  // S2E_PLUGINS_REQUIEM_BINARY_EXPR_EVALUATOR_H
