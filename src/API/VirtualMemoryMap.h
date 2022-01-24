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

#ifndef S2E_PLUGINS_CRAX_VIRTUAL_MEMORY_MAP_H
#define S2E_PLUGINS_CRAX_VIRTUAL_MEMORY_MAP_H

#include <s2e/S2EExecutionState.h>
#include <s2e/Plugins/OSMonitors/ModuleDescriptor.h>
#include <s2e/Plugins/OSMonitors/Support/MemoryMap.h>

#include <set>
#include <string>
#include <vector>

namespace s2e::plugins::crax {

// XXX: The MemoryMap plugin also has a similar structure
// called "MemoryMapRegion" (an interval map),
// and maybe we can use that structure instead.
struct MemoryRegion {
    uint64_t start;
    uint64_t end;
    MemoryMapRegionType prot;
    std::string image;
};

struct MemoryRegionCmp {
    bool operator ()(const MemoryRegion &r1, const MemoryRegion &r2) const {
        return r1.start < r2.start;
    }
};

// An enhanced version of MemoryMapRegionManager from libs2eplugins.
//
// VirtualMemoryMap, abbreviated as "VMMap" or "vmmap", provides
// the interface to do the following for the target (vulnerable) process:
// 1. enumerate the mapped memory regions, including [stack].
// 2. associate the mapped memory regions with various ELF files and permissions.
class VirtualMemoryMap {
public:
    VirtualMemoryMap()
        : m_memoryMap(),
          m_mappedSections() {}

    void initialize();

    [[nodiscard]]
    std::set<MemoryRegion, MemoryRegionCmp> getMapInfo(S2EExecutionState *state);

    void dump(S2EExecutionState *state);

private:
    void onModuleLoad(S2EExecutionState *state,
                      const ModuleDescriptor &md);

    // Rounds down address to the nearest page boundary, rounds up
    // address + size to the nearest page boundary.
    // e.g., address==1 and size==2 => start==0 and end == 0x1000;
    static void computeStartEndAddress(uint64_t address,
                                       uint64_t size,
                                       uint64_t &start,
                                       uint64_t &end) {
        start = address & TARGET_PAGE_MASK;
        end = (address + size + (TARGET_PAGE_SIZE - 1)) & TARGET_PAGE_MASK;
    }


    MemoryMap *m_memoryMap;
    ModuleSections m_mappedSections;
};

}  // namespace s2e::plugins::crax

#endif  // S2E_PLUGINS_CRAX_VIRTUAL_MEMORY_MAP_H
