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

#ifndef S2E_PLUGINS_CRAX_PWNLIB_ELF_H
#define S2E_PLUGINS_CRAX_PWNLIB_ELF_H

#include <s2e/Plugins/CRAX/Pwnlib/Function.h>

#include <pybind11/embed.h>

#include <map>
#include <string>

namespace s2e::plugins::crax {

// Forward declaration
class Exploit;

class ELF {
public:
    using SymbolMap = std::map<std::string, uint64_t>;
    using InverseSymbolMap = std::map<uint64_t, std::string>;
    using FunctionMap = std::map<std::string, Function>;

    struct Checksec {
        Checksec(const std::string &filename);
        bool hasCanary;
        bool hasFullRELRO;
        bool hasNX;
        bool hasPIE;
    };

    explicit ELF(const std::string &filename); 

    const SymbolMap &symbols() const { return m_symbols; }
    const SymbolMap &plt() const { return m_plt; }
    const SymbolMap &got() const { return m_got; }
    const InverseSymbolMap &inversePlt() const { return m_inversePlt; }
    const FunctionMap &functions() const { return m_functions; }
    uint64_t bss() const;

    uint64_t getRuntimeAddress(uint64_t offset) const;
    uint64_t getRuntimeAddress(const std::string &symbol) const;
    uint64_t rebaseAddress(uint64_t address, uint64_t newBase) const;
    inline bool hasSymbol(const std::string &symbol) const {
        return m_symbols.find(symbol) != m_symbols.end();
    }

    const std::string &getFilename() const { return m_filename; }
    const std::string &getVarPrefix() const { return m_varPrefix; }
    uint64_t getBase() const { return m_base; }
    void setBase(uint64_t base) { m_base = base; }

    const Exploit &getExploit() const;

    static constexpr uint64_t getDefaultElfBase() {
        return 0x400000;
    }

    const Checksec checksec;

private:
    InverseSymbolMap buildInversePlt();
    FunctionMap buildFunctionMap();

    pybind11::object m_elf;
    SymbolMap m_symbols;
    SymbolMap m_plt;
    SymbolMap m_got;
    InverseSymbolMap m_inversePlt;
    FunctionMap m_functions;

    std::string m_filename;
    std::string m_varPrefix;
    uint64_t m_base;
};

}  // namespace s2e::plugins::crax

#endif  // S2E_PLUGINS_CRAX_PWNLIB_ELF_H
