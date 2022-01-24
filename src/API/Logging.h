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

#ifndef S2E_PLUGINS_CRAX_LOGGING_H
#define S2E_PLUGINS_CRAX_LOGGING_H

#include <llvm/Support/raw_ostream.h>
#include <s2e/S2EExecutionState.h>

namespace s2e::plugins::crax {

// This logging module provides straightforward logging APIs with
// C++-style streams. There are three severity levels: INFO, DEBUG and WARN.
enum LogLevel {
    INFO,
    DEBUG,
    WARN
};

template <enum LogLevel T>
llvm::raw_ostream &log(S2EExecutionState *state = nullptr);

template <>
[[nodiscard]]
llvm::raw_ostream &log<LogLevel::INFO>(S2EExecutionState *state);

template <>
[[nodiscard]]
llvm::raw_ostream &log<LogLevel::DEBUG>(S2EExecutionState *state);

template <>
[[nodiscard]]
llvm::raw_ostream &log<LogLevel::WARN>(S2EExecutionState *state);

}  // namespace s2e::plugins::crax

#endif  // S2E_PLUGINS_CRAX_LOGGING_H
