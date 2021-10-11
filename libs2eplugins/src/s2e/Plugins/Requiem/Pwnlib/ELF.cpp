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

#include <pybind11/embed.h>
#include <pybind11/stl.h>

#include "ELF.h"

namespace py = pybind11;

namespace s2e::plugins::requiem {

ELF::ELF(py::module pwnlib,
         const std::string &filename)
    : m_pwnlib(pwnlib),
      m_elf(pwnlib.attr("elf").attr("ELF").call(filename)) {}


ELF::SymbolMap ELF::symbols() const {
    return m_elf.attr("symbols").cast<ELF::SymbolMap>();
}

ELF::FunctionMap ELF::functions() const {
    // The ELF class from pwntools is huge and I don't want to
    // introduce the entire of it into requiem, so I'll perform
    // manual conversion here.
    ELF::FunctionMap ret;
    py::dict functionDict = m_elf.attr("functions");

    for (const auto &item : functionDict) {
        auto name = item.first.cast<std::string>();
        auto func = item.second.cast<py::object>();

        ret[name] = {
            func.attr("name").cast<std::string>(),
            func.attr("address").cast<uint64_t>(),
            func.attr("size").cast<uint64_t>()
        };
    }
    return ret;
}

uint64_t ELF::bss() const {
    return m_elf.attr("bss").call().cast<uint64_t>();
}

}  // namespace s2e::plugins::requiem
