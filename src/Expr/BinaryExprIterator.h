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

#ifndef S2E_PLUGINS_CRAX_BINARY_EXPR_ITERATOR_H
#define S2E_PLUGINS_CRAX_BINARY_EXPR_ITERATOR_H

#include <klee/Expr.h>

#include <iterator>
#include <memory>
#include <stack>

namespace klee {

// This is CRAX's extension to klee.
//
// Given an expression tree (where each node of the tree is either a BinaryExpr or ConstantExpr),
// this forward iterator enables the user to easily traverse through the tree in the desired
// traversal order (i.e., PRE_ORDER, IN_ORDER, and POST_ORDER) which can be specified via
// template argument `S`.
//
// Example usage:
//
// ref<Expr> root = ...;
//
// for (auto it = BinaryExprIterator<IterStrategy::IN_ORDER>::begin(root);
//      it != decltype(it)::end();
//      it++) {
//     // Do something with *it, where *it is of type ref<Expr>.
// }

enum class IterStrategy {
    PRE_ORDER,
    IN_ORDER,
    POST_ORDER,
    LEVEL_ORDER
};


// Forward declaration.
template <IterStrategy S>
class BinaryExprIterator;


namespace detail {

template <IterStrategy S>
class __BaseBinaryExprIterator
    : public std::iterator<std::forward_iterator_tag, Expr> {

public:
    bool operator==(const BinaryExprIterator<S> &r) const {
        return m_currentNode.get() == r.m_currentNode.get();
    }

    bool operator!=(const BinaryExprIterator<S> &r) const {
        return m_currentNode.get() != r.m_currentNode.get();
    }

    // Pre-increment
    auto operator++() -> decltype(*this) {
        step();
        return *this;
    }

    // Post-increment
    auto operator++(int) -> decltype(auto) {
        step();
        return *this;
    }

    const ref<Expr> &operator*() const {
        return m_currentNode;
    }

    ref<Expr> &operator*() {
        return m_currentNode;
    }

    virtual void step() = 0;

    static BinaryExprIterator<S> begin(const ref<Expr> &e) {
        return BinaryExprIterator<S>(e);
    }

    static BinaryExprIterator<S> end() {
        return BinaryExprIterator<S>();
    }

protected:
    __BaseBinaryExprIterator()
        : m_currentNode(),
          m_stack() {}

    explicit __BaseBinaryExprIterator(const ref<Expr> &root)
        : m_currentNode(),
          m_stack(std::make_shared<std::stack<ref<Expr>>>()) {
        assert(root && m_stack);
    }

    // Since klee's ref is intrusive (which is not suitable for std::stack),
    // we'll use std::shared_ptr here.
    ref<Expr> m_currentNode;
    std::shared_ptr<std::stack<ref<Expr>>> m_stack;
};

}  // namespace detail


// Primary template.
template <IterStrategy S>
class BinaryExprIterator {};


// Explicit (full) template specialization [with S = IterStrategy::PRE_ORDER].
template <>
class BinaryExprIterator<IterStrategy::PRE_ORDER>
    : public detail::__BaseBinaryExprIterator<IterStrategy::PRE_ORDER> {

    friend class detail::__BaseBinaryExprIterator<IterStrategy::PRE_ORDER>;

protected:
    BinaryExprIterator()
        : detail::__BaseBinaryExprIterator<IterStrategy::PRE_ORDER>() {}

    explicit BinaryExprIterator(const ref<Expr> &root)
        : detail::__BaseBinaryExprIterator<IterStrategy::PRE_ORDER>(root) {
        m_stack->push(root);
        step();
    }

    virtual void step() override {
        if (m_stack->empty()) {
            m_currentNode = nullptr;
            return;
        }

        ref<Expr> node = m_stack->top();
        m_stack->pop();

        m_currentNode = node;

        if (auto r = node->getKid(1)) {
            m_stack->push(r);
        }
        if (auto l = node->getKid(0)) {
            m_stack->push(l);
        }
    }
};


// Explicit (full) template specialization [with S = IterStrategy::IN_ORDER].
template <>
class BinaryExprIterator<IterStrategy::IN_ORDER>
    : public detail::__BaseBinaryExprIterator<IterStrategy::IN_ORDER> {

    friend class detail::__BaseBinaryExprIterator<IterStrategy::IN_ORDER>;

protected:
    BinaryExprIterator()
        : detail::__BaseBinaryExprIterator<IterStrategy::IN_ORDER>() {}

    explicit BinaryExprIterator(const ref<Expr> &root)
        : detail::__BaseBinaryExprIterator<IterStrategy::IN_ORDER>(root) {
        ref<Expr> node = root;
        while (node) {
            m_stack->push(node);
            node = node->getKid(0);
        }
        step();
    }

    virtual void step() override {
        if (m_stack->empty()) {
            m_currentNode = nullptr;
            return;
        }

        ref<Expr> node = m_stack->top();
        m_stack->pop();

        m_currentNode = node;
        ref<Expr> r = node->getKid(1);

        while (r) {
            m_stack->push(r);
            r = r->getKid(0);
        }
    }
};


// Explicit (full) template specialization [with S = IterStrategy::POST_ORDER].
template <>
class BinaryExprIterator<IterStrategy::POST_ORDER>
    : public detail::__BaseBinaryExprIterator<IterStrategy::POST_ORDER> {

    friend class detail::__BaseBinaryExprIterator<IterStrategy::POST_ORDER>;

protected:
    BinaryExprIterator()
        : detail::__BaseBinaryExprIterator<IterStrategy::POST_ORDER>(),
          m_localRootNode() {}

    explicit BinaryExprIterator(const ref<Expr> &root)
        : detail::__BaseBinaryExprIterator<IterStrategy::POST_ORDER>(root),
          m_localRootNode(root) {
        step();
    }

    virtual void step() override {
        if (!m_localRootNode && m_stack->empty()) {
            m_currentNode = nullptr;
            return;
        }

        while (true) {
            while (m_localRootNode) {
                if (auto r = m_localRootNode->getKid(1)) {
                    m_stack->push(r);
                }
                m_stack->push(m_localRootNode);
                m_localRootNode = m_localRootNode->getKid(0);
            }

            m_localRootNode = m_stack->top();
            m_stack->pop();

            if (m_localRootNode->getKid(1) &&
                m_stack->size() &&
                m_stack->top() == m_localRootNode->getKid(1)) {
                m_stack->pop();
                m_stack->push(m_localRootNode);
                m_localRootNode = m_localRootNode->getKid(1);
            } else {
                m_currentNode = m_localRootNode;
                m_localRootNode = nullptr;
                break;
            }
        }
    }

private:
    ref<Expr> m_localRootNode;
};

}  // namespace klee

#endif  // S2E_PLUGINS_CRAX_BINARY_EXPR_ITERATOR_H
