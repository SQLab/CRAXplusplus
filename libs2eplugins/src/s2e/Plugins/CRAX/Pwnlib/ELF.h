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

class ELF {
public:
    using SymbolMap = std::map<std::string, uint64_t>;
    using FunctionMap = std::map<std::string, Function>;

    struct Checksec {
        Checksec(const std::string &filename);

        bool hasCanary;
        bool hasFullRELRO;
        bool hasNX;
        bool hasPIE;
    };

    ELF(const std::string &filename); 

    SymbolMap symbols() const;
    SymbolMap got() const;
    FunctionMap functions() const;
    uint64_t bss() const;

    uint64_t getRuntimeAddress(const std::string &symbol) const;

    const ELF::Checksec &getChecksec() const { return m_checksec; }

    uint64_t getBase() const { return m_base; }
    void setBase(uint64_t base) { m_base = base; }

    uint64_t getCanary() const { return m_canary; }
    void setCanary(uint64_t canary) { m_canary = canary; }

private:
    pybind11::object m_elf;
    ELF::Checksec m_checksec;
    uint64_t m_base;
    uint64_t m_canary;
};

}  // namespace s2e::plugins::crax

#endif  // S2E_PLUGINS_CRAX_PWNLIB_ELF_H
