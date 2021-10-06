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

#ifndef S2E_PLUGINS_REQUIEM_MEMORY_MANAGER_H
#define S2E_PLUGINS_REQUIEM_MEMORY_MANAGER_H

#include <s2e/S2EExecutionState.h>
#include <s2e/Plugins/OSMonitors/Support/MemoryMap.h>

#include <map>

namespace s2e::plugins::requiem {

// Forward declaration
class Requiem;

class MemoryManager {
public:
    MemoryManager(Requiem &ctx);
    void initialize();

    // Determine if the given memory area contains symbolic data.
    [[nodiscard]]
    bool isSymbolic(uint64_t virtAddr, uint64_t size) const;

    // Read symbolic data from memory.
    [[nodiscard]]
    klee::ref<klee::Expr> readSymbolic(uint64_t virtAddr, uint64_t size) const;

    // Read concrete data from memory.
    [[nodiscard]]
    std::vector<uint8_t> readConcrete(uint64_t virtAddr, uint64_t size) const;

    // Determine if the given virtual memory address is mapped.
    [[nodiscard]]
    bool isMapped(uint64_t virtAddr) const;

    // Returns the map<addr, size> of symbolic memory.
    [[nodiscard]]
    std::map<uint64_t, uint64_t> getSymbolicMemory(uint64_t start, uint64_t end) const;

    // Show all the mapped area.
    // XXX: The MemoryMap plugin cannot intercept the stack mapping.
    void showMapInfo(uint64_t pid) const;

private:
    // S2E built-in Plugins.
    MemoryMap *m_map;

    // Requiem's attributes.
    Requiem &m_ctx;
};

}  // namespace s2e::plugins::requiem

#endif  // S2E_PLUGINS_REQUIEM_MEMORY_MANAGER_H
