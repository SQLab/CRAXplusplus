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

#include <cassert>
#include <algorithm>

#include "VirtualMemoryMap.h"

using namespace klee;

namespace s2e::plugins::crax {

// XXX: s_elfLabel is currently hardcoded :(
const std::string VirtualMemoryMap::s_elfLabel = "target";
const std::string VirtualMemoryMap::s_libcLabel = "libc.so.6";
const std::string VirtualMemoryMap::s_sharedLibraryLabel = "[shared library]";
const std::string VirtualMemoryMap::s_ldsoLabel = "ld-linux-x86-64.so.2";
const std::string VirtualMemoryMap::s_stackLabel = "[stack]";

VirtualMemoryMap::Allocator VirtualMemoryMap::s_alloc;

void VirtualMemoryMap::initialize() {
    m_memoryMap = g_s2e->getPlugin<MemoryMap>();
    assert(m_memoryMap);

    m_moduleMap = g_s2e->getPlugin<ModuleMap>();
    assert(m_moduleMap);
}


void VirtualMemoryMap::rebuild(S2EExecutionState *state) {
    uint64_t pid = g_crax->getTargetProcessPid();
    assert(pid && "You're probably trying to rebuild vmmap too early");

    // Rebuild vmmap using the information from MemoryMap and ModuleMap.
    auto memoryMapCb = [this, state, pid](uint64_t start,
                                          uint64_t end,
                                          MemoryMapRegionType type) -> bool {
        auto region = std::make_shared<RegionDescriptor>();

        // Update region's permission.
        region->r = type & MM_READ;
        region->w = type & MM_WRITE;
        region->x = type & MM_EXEC;

        // Check if this memory region has a module loaded.
        ModuleDescriptorConstPtr m0 = m_moduleMap->getModule(state, pid, start);
        ModuleDescriptorConstPtr m1 = m_moduleMap->getModule(state, pid, end);

        // Maybe update region's associated module.
        if (m0 || m1) {
            assert(!(m0 && m1) || m0->Name == m1->Name);
            ModuleDescriptorConstPtr module = m0 ? m0 : m1;
            region->moduleName = module->Name;
        }

        insert(start, end, std::move(region));
        return true;
    };

    clear();
    m_memoryMap->iterateRegions(state, pid, memoryMapCb);

    // Probe the stack region only once.
    probeStackRegion(state);

    // XXX: Currently, vmmap is built by merging S2E's MemoryMap and ModuleMap.
    // ModuleMap tracks where binaries are loaded
    // However, since libc is loaded by ld.so instead of load_elf_binary(),
    // we won't be able  to know where libc resides in the (guest)
    // virtual address space of the target process, so we need to do it ourselves.
    fillDynamicLoaderRegions(state);
    fillLibcRegions(state);
    fillRemainingSharedLibsRegions(state);
    fillStackRegion(state);
}


void VirtualMemoryMap::probeStackRegion(S2EExecutionState *state) {
    if (m_stackRegionBegin) {
        return;
    }

    // XXX: Potentially inaccurate...
    uint64_t rsp = reg(state).readConcrete(Register::X64::RSP);
    uint64_t rspPage = Memory::roundDownToPageBoundary(rsp);

    m_stackRegionBegin = rspPage;
    while (mem(state).isMapped(m_stackRegionBegin)) {
        m_stackRegionBegin -= TARGET_PAGE_SIZE;
    }
    m_stackRegionBegin += TARGET_PAGE_SIZE;

    m_stackRegionEnd = rspPage;
    while (mem(state).isMapped(m_stackRegionEnd)) {
        m_stackRegionEnd += TARGET_PAGE_SIZE;
    }
    m_stackRegionEnd -= 1;
}

void VirtualMemoryMap::fillDynamicLoaderRegions(S2EExecutionState *state) {
    auto it1 = std::find_if(begin(),
                            end(),
                            [](const auto &r) { return r->moduleName == s_ldsoLabel; });

    auto rit2 = std::find_if(rbegin(),
                             rend(),
                             [](const auto &r) { return r->moduleName == s_ldsoLabel; });

    assert(it1 != end() && rit2 != rend());
    auto it2 = std::next(rit2).base();
    assert(it1 != it2 && "Only one ld-linux-x86-64.so.2 is present in vmmap");

    for (auto it = ++it1; it != it2; it++) {
        RegionDescriptorPtr region = *it;
        region->moduleName = s_ldsoLabel;
    }
}

void VirtualMemoryMap::fillLibcRegions(S2EExecutionState *state) {

}

void VirtualMemoryMap::fillRemainingSharedLibsRegions(S2EExecutionState *state) {
    // XXX: Is it possible to identify the associtated ELF file from memory?
    foreach2 (it, begin(), end()) {
        RegionDescriptorPtr region = *it;
        if (region->moduleName.empty()) {
            region->moduleName = s_sharedLibraryLabel;
        }
    }
}

void VirtualMemoryMap::fillStackRegion(S2EExecutionState *state) {
    assert(m_stackRegionBegin && m_stackRegionEnd);

    auto region = std::make_shared<RegionDescriptor>();
    region->r = true;
    region->w = true;
    region->x = false;  // XXX: inaccurate, we should parse ELF
    region->moduleName = s_stackLabel;

    insert(m_stackRegionBegin, m_stackRegionEnd, std::move(region));
}

void VirtualMemoryMap::dump(S2EExecutionState *state) {
    auto &os = log<WARN>(state);

    os << "Dummping memory map...\n"
        << "--------------- [VMMAP] ---------------\n"
        << "Start\t\tEnd\t\tPerm\tModule\n";

    foreach2 (it, begin(), end()) {
        uint64_t start = it.start();
        uint64_t end = it.stop() + 1;
        RegionDescriptorPtr region = *it;

        os << hexval(start) << '\t'
            << hexval(end) << '\t'
            << (region->r ? 'r' : '-')
            << (region->w ? 'w' : '-')
            << (region->x ? 'x' : '-') << '\t'
            << region->moduleName
            << '\n';
    }
}

uint64_t VirtualMemoryMap::getModuleBaseAddress(uint64_t address) const {
    auto it = find(address);

    // The given address is not mapped in the va_space?
    if (it == end()) {
        return 0;
    }

    RegionDescriptorPtr region = *it;
    const std::string &moduleName = region->moduleName;

    // Construct a reverse iterator from the forward iterator `it`,
    // and start searching toward lower virtual address
    // until the region has a different module.
    auto rit = std::find_if(std::make_reverse_iterator(it),
                            rend(),
                            [&moduleName](const auto &r) { return r->moduleName != moduleName; });

    if (rit == rend()) {
        return begin().start();
    }

    // At this point, we've already iterated past the target region,
    // so no need to advance `rit` before calling base().
    it = rit.base();
    return it.start();
}

}  // namespace s2e::plugins::crax
