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

#include "MemoryManager.h"

using namespace klee;

namespace s2e::plugins::requiem {

MemoryManager::MemoryManager(Requiem &ctx)
    : m_map(),
      m_ctx(ctx) {}

void MemoryManager::initialize() {
    m_map = g_s2e->getPlugin<MemoryMap>();

    if (!m_map) {
        g_s2e->getWarningsStream()
            << "MemoryManager::showMapInfo() requires MemoryMap plugin.\n";
    }
}


bool MemoryManager::isSymbolic(uint64_t virtAddr, uint64_t size) const {
    return !isa<klee::ConstantExpr>(readSymbolic(virtAddr, size));
}

ref<Expr> MemoryManager::readSymbolic(uint64_t virtAddr, uint64_t size) const {
    return m_ctx.state()->mem()->read(virtAddr, size);
}

std::vector<uint8_t> MemoryManager::readConcrete(uint64_t virtAddr, uint64_t size) const {
    std::vector<uint8_t> ret(size);
    if (!m_ctx.state()->mem()->read(virtAddr, ret.data(), size)) {
        g_s2e->getWarningsStream()
            << "Cannot read from memory: " << hexval(virtAddr) << "\n";
    }
    return ret;
}

bool MemoryManager::isMapped(uint64_t virtAddr) const {
    return m_ctx.state()->mem()->getHostAddress(virtAddr) != -1;
}

std::map<uint64_t, uint64_t>
MemoryManager::getSymbolicMemory(uint64_t start, uint64_t end) const {
    return {};
}

void MemoryManager::showMapInfo(uint64_t pid) const {
    auto &os = g_s2e->getWarningsStream();
    os << "--------------- [VMMAP] ---------------\n"
        << "Start\t\tEnd\t\tPerm\n";

    auto callback = [&os](uint64_t start,
                          uint64_t end,
                          const MemoryMapRegionType &prot) -> bool {
        // XXX: what about label and image name?
        os << hexval(start) << "\t"
            << hexval(end) << "\t"
            << (prot & MM_READ ? 'R' : '-')
            << (prot & MM_WRITE ? 'W' : '-')
            << (prot & MM_EXEC ? 'X' : '-')
            << "\n";
        return true;
    };

    m_map->iterateRegions(m_ctx.state(), pid, callback);

    // Find stack mapping.
    uint64_t rsp = m_ctx.reg().readConcrete(Register::RSP);
    uint64_t page_mask = ~(TARGET_PAGE_SIZE - 1);
    uint64_t stackBegin = 0;
    uint64_t stackEnd = 0;

    stackBegin = rsp & page_mask;
    while (isMapped(stackBegin)) {
        stackBegin -= TARGET_PAGE_SIZE;
    }
    stackBegin += TARGET_PAGE_SIZE;

    stackEnd = rsp & page_mask;
    while (isMapped(stackEnd)) {
        stackEnd += TARGET_PAGE_SIZE;
    }
    stackEnd -= TARGET_PAGE_SIZE;

    os << hexval(stackBegin) << "\t"
        << hexval(stackEnd) << "\t"
        << "RW-"
        << "\n";
}

}  // namespace s2e::plugins::requiem
