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

#ifndef S2E_PLUGINS_CRAX_MEMORY_H
#define S2E_PLUGINS_CRAX_MEMORY_H

#include <s2e/S2EExecutionState.h>
#include <s2e/Plugins/CRAX/API/VirtualMemoryMap.h>

#include <map>
#include <set>

namespace s2e::plugins::crax {

class Memory {
    friend class CRAX;

public:
    Memory() : m_state(), m_vmmap() {}

    void initialize() { m_vmmap.initialize(); }

    // Determine if the given memory area contains symbolic data.
    [[nodiscard]]
    bool isSymbolic(uint64_t virtAddr, uint64_t size) const;

    // Read symbolic data from memory.
    klee::ref<klee::Expr> readSymbolic(uint64_t virtAddr,
                                       klee::Expr::Width size) const;

    // Read concrete data from memory.
    std::vector<uint8_t> readConcrete(uint64_t virtAddr,
                                      uint64_t size,
                                      bool concretize = true) const;

    // Write symbolic data to memory.
    bool writeSymbolic(uint64_t virtAddr, const klee::ref<klee::Expr> &value);

    // Write concrete data to memory.
    bool writeConcrete(uint64_t virtAddr, const std::vector<uint8_t> &bytes);

    // Determine if the given virtual memory address is mapped.
    [[nodiscard]]
    bool isMapped(uint64_t virtAddr) const;

    // Search for a sequence of bytes `needle` in memory,
    // and return the addresses of all matches.
    [[nodiscard]]
    std::vector<uint64_t> search(const std::vector<uint8_t> &needle) const;

    // Returns the map<addr, size> of symbolic memory.
    [[nodiscard]]
    std::map<uint64_t, uint64_t> getSymbolicMemory() const;

    // Get all the mapped memory region.
    [[nodiscard]]
    const VirtualMemoryMap &vmmap() const;

    // Show all the mapped memory region.
    void showMapInfo() const;


    static constexpr uint64_t roundDownToPageBoundary(uint64_t address) {
        return address & TARGET_PAGE_MASK;
    }

    static constexpr uint64_t roundUpToPageBoundary(uint64_t address) {
        return (address + (TARGET_PAGE_SIZE - 1)) & TARGET_PAGE_MASK;
    }

private:
    S2EExecutionState *m_state;
    mutable VirtualMemoryMap m_vmmap;
};


Memory &mem(S2EExecutionState *state = nullptr);

}  // namespace s2e::plugins::crax

#endif  // S2E_PLUGINS_CRAX_MEMORY_H
