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

#include <s2e/Plugins/CRAX/CRAX.h>
#include <s2e/Plugins/CRAX/Utils/Subprocess.h>
#include <s2e/Plugins/CRAX/Utils/StringUtil.h>

#include <cassert>
#include <string>
#include <vector>
#include <pybind11/embed.h>
#include <pybind11/stl.h>

#include "ELF.h"

namespace py = pybind11;

namespace s2e::plugins::crax {

ELF::ELF(const std::string &filename)
    : checksec(filename),
      m_elf(CRAX::s_pwnlib.attr("elf").attr("ELF").call(filename)),
      m_symbols(),
      m_got(),
      m_functions(),
      m_base() {
    m_symbols = m_elf.attr("symbols").cast<ELF::SymbolMap>();
    m_got = m_elf.attr("got").cast<ELF::SymbolMap>();

    // The ELF class from pwnlib is huge and I don't want to
    // introduce the entire of it into crax, so I'll perform
    // manual conversion here.
    py::dict functionDict = m_elf.attr("functions");

    for (const auto &item : functionDict) {
        auto name = item.first.cast<std::string>();
        auto func = item.second.cast<py::object>();

        m_functions[name] = {
            func.attr("name").cast<std::string>(),
            func.attr("address").cast<uint64_t>(),
            func.attr("size").cast<uint64_t>()
        };
    }
}


uint64_t ELF::bss() const {
    return m_elf.attr("bss").call().cast<uint64_t>();
}

uint64_t ELF::getRuntimeAddress(uint64_t offset) const {
    assert((!checksec.hasPIE || m_base) && "PIE enabled, but `m_base` uninitialized!");
    return (!checksec.hasPIE) ? offset : m_base + offset;
}

uint64_t ELF::getRuntimeAddress(const std::string &symbol) const {
    return getRuntimeAddress(symbols().at(symbol));
}

uint64_t ELF::rebaseAddress(uint64_t address, uint64_t newBase) const {
    assert(address >= m_base);
    return newBase + address - m_base;
}


ELF::Checksec::Checksec(const std::string &filename)
    : hasCanary(),
      hasFullRELRO(),
      hasNX(),
      hasPIE() {
    // Get the output of `checksec --file <m_elfFilename>`
    // and store it in `output`.
    subprocess::popen checksec("checksec", {"--file", filename});
    std::string output = toString(checksec.stderr());

    // Example output:
    // [*] '/lib/x86_64-linux-gnu/libc.so.6'
    //     Arch:     amd64-64-little
    //     RELRO:    Partial RELRO
    //     Stack:    Canary found
    //     NX:       NX enabled
    //     PIE:      PIE enabled
    // 
    // The first thing to do is checking if the output seems correct.
    assert(startsWith(output, "[*] ") && "checksec not installed?");
    output = output.substr(output.find('\n') + 1);
    output = strip(output);

    for (const auto &line : split(output, '\n')) {
        std::vector<std::string> keyVal = split(line, ':');
        assert(keyVal.size() == 2);
        std::string key = strip(keyVal[0]);
        std::string val = strip(keyVal[1]);

        if (key == "RELRO") {
            hasFullRELRO = (val == "Full RELRO");
        } else if (key == "Stack") {
            hasCanary = (val == "Canary found");
        } else if (key == "NX") {
            hasNX = (val == "NX enabled");
        } else if (key == "PIE") {
            hasPIE = (val == "PIE enabled");
        }
    }
}

}  // namespace s2e::plugins::crax
