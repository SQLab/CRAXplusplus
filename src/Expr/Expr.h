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

#ifndef S2E_PLUGINS_CRAX_EXPR_H
#define S2E_PLUGINS_CRAX_EXPR_H

#include <klee/Expr.h>
#include <s2e/Plugins/CRAX/Exploit.h>
#include <s2e/Plugins/CRAX/Pwnlib/ELF.h>
#include <s2e/Plugins/CRAX/Utils/StringUtil.h>
#include <s2e/Plugins/CRAX/Utils/TypeTraits.h>

#include <cassert>
#include <cstdlib>
#include <functional>
#include <string>
#include <vector>
#include <utility>

using s2e::plugins::crax::format;
using s2e::plugins::crax::toByteString;
using s2e::plugins::crax::dependent_false_v;

namespace klee {

// This is CRAX's extension to klee.
//
// In a generated exploit script, each line contains a statement such as:
//
// 1. payload = p64(0x401060)
// 2. payload = p64(target_base + elf.sym['read'] + 0x30 * 2)
// 3. payload = p64(__libc_csu_init_gadget1)
//
// Analysis:
//
// 1. The simple 0x401060 can be represented by a klee::ConstantExpr.
// 2. `target_base + elf.sym['read']` will be represented by our BaseOffsetExpr
//     which essentially is a klee::AddExpr.
// 3. `__libc_csu_init_gadget1` is a symbol used by the script itself
//     and can be rewritten as `target_base + __libc_csu_init_gadget1`,
//     so essentially it is also a klee::AddExpr.
class BaseOffsetExpr : public AddExpr {
    using Exploit = s2e::plugins::crax::Exploit;
    using ELF = s2e::plugins::crax::ELF;

public:
    // Supported base types
    enum class BaseType {
        SYM,
        GOT,
        BSS,
        VAR,
    };

    virtual ~BaseOffsetExpr() override = default;

    virtual unsigned getNumKids() const override {
        return 0;
    }

    virtual ref<Expr> getKid(unsigned i) const override {
        return nullptr;
    }

    static ref<Expr> alloc(const ref<ConstantExpr> &lce,
                           const ref<ConstantExpr> &rce,
                           const std::string &strBase,
                           const std::string &strOffset) {
        return ref<Expr>(new BaseOffsetExpr(lce, rce, strBase, strOffset));
    }

    // Create a BaseOffsetExpr that represents one of the following:
    //
    // 1. "target_base + elf.sym['read']"
    //    => BaseOffsetExpr::create<BaseType::SYM>(elf, "read");
    //
    // 2. "target_base + elf.got['read']"
    //    => BaseOffsetExpr::create<BaseType::GOT>(elf, "read");
    //
    // 3. "target_base + elf.bss()"
    //    => BaseOffsetExpr::create<BaseType::BSS>(elf);
    //
    // 4. "target_base + __libc_csu_init_gadget1"
    //    => BaseOffsetExpr::create<BaseType::VAR>(elf, "__libc_csu_init_gadget1")
    template <BaseType BT>
    static ref<Expr> create(const ELF &elf, const std::string &symbol = "") {
        uint64_t offset = 0;
        std::string strOffset;
        const std::string &prefix = elf.getVarPrefix();

        if constexpr (BT == BaseType::SYM) {
            const auto &symbolMap = elf.symbols();
            auto it = symbolMap.find(symbol);
            assert(it != symbolMap.end() && "Symbol doesn't exist in elf.sym");
            offset = it->second;
            strOffset = format("%s.sym['%s']", prefix.c_str(), symbol.c_str());

        } else if constexpr (BT == BaseType::GOT) {
            const auto &gotMap = elf.got();
            auto it = gotMap.find(symbol);
            assert(it != gotMap.end() && "Symbol doesn't exist in elf.got");
            offset = it->second;
            strOffset = format("%s.got['%s']", prefix.c_str(), symbol.c_str());

        } else if constexpr (BT == BaseType::BSS) {
            offset = elf.bss();
            strOffset = format("%s.bss()", prefix.c_str());

        } else if constexpr (BT == BaseType::VAR) {
            const Exploit &exploit = elf.getExploit();
            auto it = exploit.getSymtab().find(symbol);
            assert(it != exploit.getSymtab().end() && "Var doesn't exist in script's symtab");
            offset = it->second;
            strOffset = symbol;

        } else {
            // XXX: Uncomment the following line when S2E upstream upgrades to clang > 13.0.1
            //static_assert(dependent_false_v<BT>, "Unsupported base type :(");
        }

        return create(elf.getBase(), offset, prefix + "_base", std::move(strOffset));
    }

    // Create a BaseOffsetExpr that represents an offset from `elf.getBase()`,
    // E.g. "target_base + 0x666"
    template <BaseType T>
    static ref<Expr> create(const ELF &elf, uint64_t offset) {
        static_assert(T == BaseType::VAR);
        return create(elf.getBase(), offset, elf.getVarPrefix() + "_base", "");
    }

    // Method for support type inquiry through isa, cast, and dyn_cast.
    static bool classof(const Expr *e) {
        // XXX: The normal way of implementing BaseOffsetExpr::classof() is
        // adding our typeinfo to klee::Expr::Kind enum. However, since I don't
        // want to touch klee's source code, I'll simply forward the job
        // to C++'s vtable. Perhaps this can be optimized later.
        return dynamic_cast<const BaseOffsetExpr *>(e);
    }

    // Method for support type inquiry through isa, cast, and dyn_cast.
    static bool classof(const BaseOffsetExpr *) {
        return true;
    }

    ref<ConstantExpr> toConstantExpr() const {
        auto lce = dyn_cast<ConstantExpr>(AddExpr::getKid(0));
        auto rce = dyn_cast<ConstantExpr>(AddExpr::getKid(1));

        assert(lce && rce);
        return lce->Add(rce);
    }

    std::string toString() const {
        std::string strLeft = m_strBase;
        std::string strRight;

        if (m_strOffset.size()) {
            strRight = m_strOffset;
        } else {
            auto rce = dyn_cast<ConstantExpr>(right);
            strRight = format("0x%llx", rce->getZExtValue());
        }
        return strLeft + " + " + strRight;
    }
 
    uint64_t getZExtValue() const {
        return toConstantExpr()->getZExtValue();
    }
   
private:
    BaseOffsetExpr(const ref<ConstantExpr> &lce,
                   const ref<ConstantExpr> &rce,
                   const std::string &strBase,
                   const std::string &strOffset)
        : AddExpr(lce, rce),
          m_strBase(strBase),
          m_strOffset(strOffset) {
        assert(strBase.size() || strOffset.size());
    }

    static ref<Expr> create(uint64_t base,
                            uint64_t offset,
                            std::string strBase = "",
                            std::string strOffset = "") {
        auto lce = ConstantExpr::create(base, Expr::Int64);
        auto rce = ConstantExpr::create(offset, Expr::Int64);

        return alloc(lce, rce, strBase, strOffset);
    }

    std::string m_strBase;
    std::string m_strOffset;
};


// A placeholder expr which supports storing user data of arbitrary type.
// It is up to the user to decide what to do with the underlying user data.
template <typename T>
class PlaceholderExpr : public Expr {
public:
    virtual ~PlaceholderExpr() override = default;

    virtual Kind getKind() const override {
        // Under normal circumstances, this expr shouldn't exist.
        // It is supposed to be replaced sometime before expr evaluation.
        return Expr::InvalidKind;
    }

    virtual Width getWidth() const override {
        return Expr::InvalidWidth;
    }

    virtual unsigned getNumKids() const override {
        return 0;
    }

    virtual ref<Expr> getKid(unsigned i) const override {
        return nullptr;
    }

    virtual ref<Expr> rebuild(ref<Expr> kids[]) const override {
        std::abort();
    }

    template <typename U>
    static ref<Expr> alloc(U &&userData) {
        return ref<Expr>(new PlaceholderExpr(std::forward<U>(userData)));
    }

    template <typename U>
    static ref<Expr> create(U &&userData) {
        return alloc(std::forward<U>(userData));
    }

    // Method for support type inquiry through isa, cast, and dyn_cast.
    static bool classof(const Expr *e) {
        return dynamic_cast<const PlaceholderExpr *>(e);
    }

    // Method for support type inquiry through isa, cast, and dyn_cast.
    static bool classof(const PlaceholderExpr *) {
        return true;
    }

    const T &getUserData() const {
        return m_userData;
    }

    void setUserData(const T &userData) {
        m_userData = userData;
    }

private:
    PlaceholderExpr(const T &userData)
        : Expr(),
          m_userData(userData) {}

    PlaceholderExpr(T &&userData)
        : Expr(),
          m_userData(std::move(userData)) {}

    T m_userData;
};


// Sometimes we want to send a sequence of bytes whose size is not simply a QWORD.
class ByteVectorExpr : public Expr {
public:
    virtual ~ByteVectorExpr() override = default;

    virtual Kind getKind() const override {
        return Expr::Constant;
    }

    virtual Width getWidth() const override {
        return 8 * m_bytes.size();  // number of bits
    }

    virtual unsigned getNumKids() const override {
        return 0;
    }

    virtual ref<Expr> getKid(unsigned i) const override {
        return nullptr;
    }

    virtual ref<Expr> rebuild(ref<Expr> kids[]) const override {
        std::abort();
    }

    template <typename InputIt>
    static ref<Expr> alloc(InputIt first, InputIt last) {
        return ref<Expr>(new ByteVectorExpr(std::vector<uint8_t>(first, last)));
    }

    template <typename T>
    static ref<Expr> create(const T &container) {
        return alloc(container.begin(), container.end());
    }

    // Method for support type inquiry through isa, cast, and dyn_cast.
    static bool classof(const Expr *e) {
        return dynamic_cast<const ByteVectorExpr*>(e);
    }

    // Method for support type inquiry through isa, cast, and dyn_cast.
    static bool classof(const ByteVectorExpr *) {
        return true;
    }

    const std::vector<uint8_t> &getBytes() const {
        return m_bytes;
    }

    std::string toString() const {
        std::string byteString = toByteString(m_bytes.begin(), m_bytes.end());
        return format("b'%s'", byteString.c_str());
    }

private:
    ByteVectorExpr(std::vector<uint8_t> &&bytes)
        : Expr(),
          m_bytes(std::move(bytes)) {}

    std::vector<uint8_t> m_bytes;
};


// A flexible expression which allows the caller to perform arbitrary actions.
class LambdaExpr : public Expr {
    using CallbackType = std::function<void ()>;

public:
    virtual ~LambdaExpr() override = default;

    virtual Kind getKind() const override {
        return Expr::InvalidKind;
    }

    virtual Width getWidth() const override {
        return Expr::InvalidWidth;
    }

    virtual unsigned getNumKids() const override {
        return 0;
    }

    virtual ref<Expr> getKid(unsigned i) const override {
        return nullptr;
    }

    virtual ref<Expr> rebuild(ref<Expr> kids[]) const override {
        std::abort();
    }

    template <typename U>
    static ref<Expr> alloc(U &&cb) {
        return ref<Expr>(new LambdaExpr(std::forward<U>(cb)));
    }

    template <typename U>
    static ref<Expr> create(U &&cb) {
        return alloc(std::forward<U>(cb));
    }

    // Method for support type inquiry through isa, cast, and dyn_cast.
    static bool classof(const Expr *e) {
        return dynamic_cast<const LambdaExpr *>(e);
    }

    // Method for support type inquiry through isa, cast, and dyn_cast.
    static bool classof(const LambdaExpr *) {
        return true;
    }

    void operator()() const {
        m_callback();
    }

private:
    LambdaExpr(const CallbackType &cb)
        : Expr(),
          m_callback(cb) {}

    LambdaExpr(CallbackType &&cb)
        : Expr(),
          m_callback(std::move(cb)) {}

    CallbackType m_callback;
};

}  // namespace klee

#endif  // S2E_PLUGINS_CRAX_EXPR_H
