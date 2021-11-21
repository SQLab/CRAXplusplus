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

#ifndef S2E_PLUGINS_REQUIEM_EXPR_H
#define S2E_PLUGINS_REQUIEM_EXPR_H

#include <s2e/Plugins/Requiem/Pwnlib/ELF.h>

#include <klee/Expr.h>

#include <string>

namespace klee {

// This is Requiem's extension to klee.
//
// In a generated exploit script, each line contains a statement such as:
// 1. payload = 0x401060
// 2. payload = elf_base + elf.sym['read'] + 0x30 * 2
//
// The simple 0x401060 can be represented by a klee::ConstantExpr,
// and `elf_base + elf.sym['read']` will be represented by our SymbolAccessExpr
// which essentially is a klee::AddExpr.

class SymbolAccessExpr : public AddExpr {
    using ELF = s2e::plugins::requiem::ELF;

private:
    SymbolAccessExpr(const ref<ConstantExpr> &l,
                     const ref<ConstantExpr> &r,
                     const std::string &symbol)
        : AddExpr(l, r),
          m_symbol(symbol) {}

public:
    virtual ~SymbolAccessExpr() = default;

    static ref<Expr> alloc(const ref<ConstantExpr> &l,
                           const ref<ConstantExpr> &r,
                           const std::string &symbol) {
        return ref<Expr>(new SymbolAccessExpr(l, r, symbol));
    }

    static ref<Expr> create(const ELF &image, const std::string &symbol) {
        auto cl = ConstantExpr::create(image.getBase(), Expr::Int64);
        auto cr = ConstantExpr::create(image.symbols()[symbol], Expr::Int64);
        return alloc(cl, cr, symbol);
    }

    // Method for support type inquiry through isa, cast, and dyn_cast.
    static bool classof(const Expr *E) {
        // XXX: The normal way of implementing SymbolAccessExpr::classof() is
        // adding our typeinfo to klee::Expr::Kind enum. However, since I don't
        // want to touch klee's source code, I'll simply forward the job
        // to C++'s vtable. Perhaps this can be optimized later.
        return dynamic_cast<const SymbolAccessExpr *>(E) != nullptr;
    }

    // Method for support type inquiry through isa, cast, and dyn_cast.
    static bool classof(const SymbolAccessExpr *) {
        return true;
    }

    int64_t toInt64() const {
        //return AddExpr::getKid(0) + AddExpr::getKid(1);
        return 0;
    }

    std::string toString() const {
        return "elf_base + elf.sym['" + m_symbol + "']";
    }
    
private:
    std::string m_symbol;
};

}  // namespace klee

#endif  // S2E_PLUGINS_REQUIEM_EXPR_H
