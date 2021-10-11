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
#include <s2e/Plugins/Requiem/Utils/Algorithm.h>

#include "MemoryManager.h"

using namespace klee;

namespace s2e::plugins::requiem {

MemoryManager::MemoryManager(Requiem &ctx)
    : m_map(),
      m_ctx(ctx) {}

void MemoryManager::initialize() {
    m_map = g_s2e->getPlugin<MemoryMap>();

    if (!m_map) {
        m_ctx.log<WARN>() << "MemoryManager::showMapInfo() requires MemoryMap plugin.\n";
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
        m_ctx.log<WARN>() << "Cannot read from memory: " << hexval(virtAddr) << "\n";
        ret.clear();
    }
    return ret;
}

bool MemoryManager::isMapped(uint64_t virtAddr) const {
    return m_ctx.state()->mem()->getHostAddress(virtAddr) != -1;
}

std::vector<uint64_t> MemoryManager::search(const std::vector<uint8_t> &needle) const {
    std::vector<uint64_t> ret;

    // Iterate over all the mapped memory regions.
    for (auto region : getMapInfo(m_ctx.getTargetProcessPid())) {
        // XXX: Some regions might be unaccessible even though it's mapped,
        // which I believe this is a bug in S2E. Just in case this happens,
        // we'll use `MemoryManager::isMapped()` to scan through every address
        // within this region until an accessible address is found.
        while (!isMapped(region.start) && region.start < region.end) {
            ++region.start;
        }

        // If the entire region is not accessible, then
        // we don't have to do anything with this region.
        if (region.start >= region.end) {
            continue;
        }

        // Read the region concretely into `haystack`,
        // and use kmp algorithm to search all the occurences of `needle`.
        std::vector<uint8_t> haystack = readConcrete(region.start, region.end - region.start);
        std::vector<uint64_t> localResult = kmp(haystack, needle);

        // `localResult` contains the offset within `haystack`, so adding
        // `region.start` to each element will turn them into valid virtual addresses.
        for (auto &r : localResult) {
            r += region.start;
        }

        // Append `localResult` to `ret`.
        ret.insert(ret.end(), localResult.begin(), localResult.end());
    }

    return ret;
}


std::map<uint64_t, uint64_t>
MemoryManager::getSymbolicMemory(uint64_t start, uint64_t end) const {
    return {};
}

std::set<MemoryRegion, MemoryRegionCmp> MemoryManager::getMapInfo(uint64_t pid) const {
    std::set<MemoryRegion, MemoryRegionCmp> ret;

    auto callback = [&ret](uint64_t start,
                           uint64_t end,
                           const MemoryMapRegionType &prot) -> bool {
        ret.insert({start, end, prot});
        return true;
    };
    
    m_map->iterateRegions(m_ctx.state(), pid, callback);

    // The MemoryMap plugin cannot keep track of the stack mapping,
    // so we have to find it by ourselves.
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

    ret.insert({stackBegin, stackEnd, MM_READ | MM_WRITE});
    return ret;
}

void MemoryManager::showMapInfo(uint64_t pid) const {
    auto &os = m_ctx.log<WARN>();

    os << "--------------- [VMMAP] ---------------\n"
        << "Start\t\tEnd\t\tPerm\n";

    for (const auto &region : getMapInfo(pid)) {
        os << hexval(region.start) << "\t"
            << hexval(region.end) << "\t"
            << (region.prot & MM_READ ? 'R' : '-')
            << (region.prot & MM_WRITE ? 'W' : '-')
            << (region.prot & MM_EXEC ? 'X' : '-')
            << "\n";
    }
}

}  // namespace s2e::plugins::requiem
