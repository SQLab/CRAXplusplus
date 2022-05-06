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

#ifndef S2E_PLUGINS_CRAX_CONSTRAINT_BUILDER_H
#define S2E_PLUGINS_CRAX_CONSTRAINT_BUILDER_H

#include <klee/Expr.h>

namespace s2e::plugins::crax {

class ConstraintBuilder {
public:
    ConstraintBuilder()
        : m_constraints(klee::ConstantExpr::create(true, klee::Expr::Bool)) {}

    explicit ConstraintBuilder(klee::ref<klee::Expr> constraint)
        : m_constraints(constraint) {}

    ConstraintBuilder(const ConstraintBuilder &r) = delete;
    ConstraintBuilder &operator=(const ConstraintBuilder &r) = delete;

    ConstraintBuilder(ConstraintBuilder &&r) = delete;
    ConstraintBuilder &operator=(ConstraintBuilder &&r) = delete;


    ConstraintBuilder& And(klee::ref<klee::Expr> constraint) {
        m_constraints = klee::AndExpr::create(m_constraints, constraint);
        return *this;
    }

    ConstraintBuilder& Or(klee::ref<klee::Expr> constraint) {
        m_constraints = klee::OrExpr::create(m_constraints, constraint);
        return *this;
    }

    klee::ref<klee::Expr> build() const {
        return m_constraints;
    }

    void clear() {
        m_constraints = klee::ConstantExpr::create(true, klee::Expr::Bool);
    }

private:
    klee::ref<klee::Expr> m_constraints;
};

}  // namespace s2e::plugins::crax

#endif  // S2E_PLUGINS_CRAX_CONSTRAINT_BUILDER_H
