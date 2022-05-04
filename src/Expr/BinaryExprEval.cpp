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

#include <s2e/Plugins/CRAX/Expr/BinaryExprIterator.h>
#include <s2e/Plugins/CRAX/Pwnlib/Util.h>
#include <s2e/Plugins/CRAX/Utils/StringUtil.h>

#include <stack>

#include "BinaryExprEval.h"

namespace klee {

namespace {

inline bool isValidOperator(const ref<Expr> &e) {
    return dyn_cast<AddExpr>(e) ||
           dyn_cast<SubExpr>(e) ||
           dyn_cast<MulExpr>(e);
}

}  // namespace

template <>
uint64_t evaluate(const ref<Expr> &e) {
    // ByteVectorExpr should only exist as expr tree's root node.
    if (auto bve = dyn_cast<ByteVectorExpr>(e)) {
        using s2e::plugins::crax::u64;
        return u64(bve->getBytes());
    }

    if (auto phe = dyn_cast<PlaceholderExpr<uint64_t>>(e)) {
        return 0;
    }

    std::stack<ref<Expr>> stack;

    // Evaluates an expr to an integer constant.
    for (auto it = BinaryExprIterator<IterStrategy::POST_ORDER>::begin(e);
         it != decltype(it)::end();
         it++) {
        ref<Expr> node = *it;

        if (auto boe = dyn_cast<BaseOffsetExpr>(node)) {
            // BaseOffsetExpr, essentially, is an AddExpr,
            // but during reverse polish notation evaluation
            // we should treat it like a ConstantExpr.
            stack.push(boe->toConstantExpr());
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
    return ce->getZExtValue();
}


template <>
std::string evaluate(const ref<Expr> &e) {
    // ByteVectorExpr should only exist as expr tree's root node.
    if (auto bve = dyn_cast<ByteVectorExpr>(e)) {
        return bve->toString();
    }

    std::string ret = "p64(";

    // Evaluates an expr to a string of infix expression,
    // e.g., "3 + 2", "0 + elf.sym['read'] + 0x30 * 2"
    for (auto it = BinaryExprIterator<IterStrategy::IN_ORDER>::begin(e);
         it != decltype(it)::end();
         it++) {
        ref<Expr> node = *it;

        if (auto boe = dyn_cast<BaseOffsetExpr>(node)) {
            ret += boe->toString();
        } else if (auto ce = dyn_cast<ConstantExpr>(node)) {
            ret += format("0x%llx", ce->getZExtValue());
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
    return ret + ')';
}

}  // namespace klee
