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
#include <optional>

namespace s2e::plugins::requiem {

class MemoryManager {
public:
    MemoryManager();
    void initialize();

    // Read from a memory address.
    [[nodiscard]]
    std::optional<std::vector<uint8_t>>
    read(S2EExecutionState *state,
         uint64_t virtAddr,
         uint64_t size);

    // Write to a memory address.
    void write(S2EExecutionState *state,
               uint64_t virtAddr,
               const std::vector<uint8_t> &data);

    // Returns the map<addr, size> of symbolic memory.
    [[nodiscard]]
    std::map<uint64_t, uint64_t> getSymbolicMemory(S2EExecutionState *state,
                                                   uint64_t start,
                                                   uint64_t end);

    // Show all the mapped area.
    // XXX: The MemoryMap plugin cannot intercept the stack mapping.
    void showMapInfo(S2EExecutionState *state, uint64_t pid) const;

private:
    MemoryMap *m_map;
};

}  // namespace s2e::plugins::requiem

#endif  // S2E_PLUGINS_REQUIEM_MEMORY_MANAGER_H
