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
#include <s2e/Plugins/CRAX/Utils/Algorithm.h>

#include <algorithm>

#include "Memory.h"

using namespace klee;

namespace s2e::plugins::crax {

Memory::Memory(CRAX &ctx)
    : m_map(),
      m_ctx(ctx),
      m_mappedSections() {}

void Memory::initialize() {
    m_map = g_s2e->getPlugin<MemoryMap>();

    if (!m_map) {
        log<WARN>() << "Memory::showMapInfo() requires MemoryMap plugin.\n";
    }
}


bool Memory::isSymbolic(uint64_t virtAddr, uint64_t size) const {
    return m_ctx.getCurrentState()->mem()->symbolic(virtAddr, size);
}

ref<Expr> Memory::readSymbolic(uint64_t virtAddr, uint64_t size) const {
    // XXX: check `size`.
    // See: klee/include/klee/Expr.h
    return m_ctx.getCurrentState()->mem()->read(virtAddr, size);
}

std::vector<uint8_t> Memory::readConcrete(uint64_t virtAddr, uint64_t size, bool concretize) const {
    std::vector<uint8_t> ret(size);

    if (concretize) {
        if (!m_ctx.getCurrentState()->mem()->read(virtAddr, ret.data(), size)) {
            log<WARN>() << "Cannot read concrete data from memory: " << hexval(virtAddr) << "\n";
            ret.clear();
        }
    } else {
        // XXX: The performance seems fast enough even though I bruteforce it byte by byte,
        // but maybe we can optimize it directly in libs2ecore at some point.
        for (uint64_t i = 0; i < size; i++) {
            // Read the underlying concrete bytes, but don't concretize them.
            if (isSymbolic(virtAddr + i, 1)) {
                if (!m_ctx.getCurrentState()->mem()->read(virtAddr + i, &ret[i], VirtualAddress, false)) {
                    log<WARN>() << "Non-concretizing read() from memory failed: " << hexval(virtAddr + i) << "\n";
                    ret.clear();
                    break;
                }
                continue;
            }
            if (!m_ctx.getCurrentState()->mem()->read(virtAddr + i, &ret[i], 1)) {
                log<WARN>() << "Cannot read concrete data from memory: " << hexval(virtAddr + i) << "\n";
                ret.clear();
                break;
            }
         }
    }

    return ret;
}

bool Memory::writeSymbolic(uint64_t virtAddr, const klee::ref<klee::Expr> &value) {
    bool success = m_ctx.getCurrentState()->mem()->write(virtAddr, value);
    if (!success) {
        log<WARN>() << "Cannot write symbolic data to memory: " << hexval(virtAddr) << "\n";
    }
    return success;
}

bool Memory::writeConcrete(uint64_t virtAddr, uint64_t value) {
    bool success = m_ctx.getCurrentState()->mem()->write(virtAddr, &value, sizeof(value));
    if (!success) {
        log<WARN>() << "Cannot write concrete data to memory: " << hexval(virtAddr) << "\n";
    }
    return success;
}

bool Memory::isMapped(uint64_t virtAddr) const {
    return m_ctx.getCurrentState()->mem()->getHostAddress(virtAddr) != -1;
}

std::vector<uint64_t> Memory::search(const std::vector<uint8_t> &needle) const {
    std::vector<uint64_t> ret;

    // Iterate over all the mapped memory regions.
    for (auto region : getMapInfo(m_ctx.getTargetProcessPid())) {
        // XXX: Some regions might be unaccessible even though it's mapped,
        // which I believe this is a bug in S2E. Just in case this happens,
        // we'll use `Memory::isMapped()` to scan through every address
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
        std::vector<uint8_t> haystack = readConcrete(region.start, region.end - region.start, /*concretize=*/false);
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
Memory::getSymbolicMemory(uint64_t start, uint64_t end) const {
    return {};
}

std::set<MemoryRegion, MemoryRegionCmp> Memory::getMapInfo(uint64_t pid) const {
    std::set<MemoryRegion, MemoryRegionCmp> ret;

    auto callback = [this, &ret](uint64_t start,
                                 uint64_t end,
                                 const MemoryMapRegionType &prot) -> bool {
        std::string image = "unknown";

        // XXX: This workaround should be overhauled!!!
        //
        // Currently, we use LinuxMonitor::onModuleLoad to keep track of
        // which binaries are loaded by linux kernel's load_elf_binary().
        // However, since libc is loaded by ld.so, we will never be able
        // to know where libc resides in the (guest) virtual address space
        // of the target process.
        //
        // Maybe we should modify s2e linux kernel (mm/util.c:vm_mmap_pgoff())
        // and return the image pathname of each mapped region from the guest kernel.
        for (const auto &section : m_mappedSections) {
            uint64_t addr = section.runtimeLoadBase + section.size;
            if (addr >= start && addr <= end) {
                image = section.name;
            }
        }

        ret.insert({start, end, prot, image});
        return true;
    };
    
    m_map->iterateRegions(m_ctx.getCurrentState(), pid, callback);

    // XXX: This workaround should be overhauled!!!
    //
    // --------------- [VMMAP] ---------------
    // Start           End             Perm    Image
    // 0x400000        0x400fff        r--     target
    // 0x401000        0x401fff        r-x     target
    // 0x402000        0x403fff        r--     target
    // 0x404000        0x404fff        rw-     target
    // 0x7fe232d7c000  0x7fe232f10fff  r-x     unknown
    // 0x7fe232f11000  0x7fe233110fff  ---     unknown
    // 0x7fe233111000  0x7fe233114fff  r--     unknown
    // 0x7fe233115000  0x7fe23311afff  rw-     unknown
    // 0x7fe23311b000  0x7fe23313dfff  r-x     ld-linux-x86-64.so.2
    // 0x7fe233334000  0x7fe233335fff  rw-     unknown              <--
    // 0x7fe23333e000  0x7fe23333efff  r--     unknown              <--
    // 0x7fe23333f000  0x7fe23333ffff  rw-     ld-linux-x86-64.so.2
    // 0x7ffe0939e000  0x7ffe093a0000  rw-     [stack]
    const std::string ld = "ld-linux-x86-64.so.2";

    auto it1 = std::find_if(ret.begin(),
                            ret.end(),
                            [&ld](const MemoryRegion &r) { return r.image == ld; });
    assert(it1 != ret.end() && "Cannot find the first ld-linux-x86-64.so.2 in vmmap.");

    auto rit2 = std::find_if(ret.rbegin(),
                             ret.rend(),
                             [&ld](const MemoryRegion &r) { return r.image == ld; });
    assert(rit2 != ret.rend() && "Cannot find the last ld-linux-x86-64.so.2 in vmmap.");

    auto it2 = std::next(rit2).base();
    assert(it1 != it2 && "Only one ld-linux-x86-64.so.2 is present in vmmap.");

    for (auto it = ++it1; it != it2; it++) {
        MemoryRegion &region = const_cast<MemoryRegion &>(*it);
        assert(region.image == "unknown");
        region.image = ld;
    }

    // Mark the rest of the unknown images as libc.
    for (auto &region : ret) {
        if (region.image == "unknown") {
            MemoryRegion &__region = const_cast<MemoryRegion &>(region);
            __region.image = "[shared library]";
        }
    }

    // The MemoryMap plugin cannot keep track of the stack mapping,
    // so we have to find it by ourselves.
    uint64_t rsp = m_ctx.reg().readConcrete(Register::X64::RSP);
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

    ret.insert({stackBegin, stackEnd, MM_READ | MM_WRITE, "[stack]"});
    return ret;
}

void Memory::showMapInfo(uint64_t pid) const {
    auto &os = log<WARN>();

    os << "Dummping memory map...\n"
        << "--------------- [VMMAP] ---------------\n"
        << "Start\t\tEnd\t\tPerm\tImage\n";

    for (const auto &region : getMapInfo(pid)) {
        os << hexval(region.start) << '\t'
            << hexval(region.end) << '\t'
            << (region.prot & MM_READ ? 'r' : '-')
            << (region.prot & MM_WRITE ? 'w' : '-')
            << (region.prot & MM_EXEC ? 'x' : '-') << '\t'
            << region.image << '\n';
    }
}

}  // namespace s2e::plugins::crax
