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

#ifndef S2E_PLUGINS_REQUIEM_BEHAVIORS_H
#define S2E_PLUGINS_REQUIEM_BEHAVIORS_H

namespace s2e::plugins::requiem {

// The abstract base class of all program's I/O-related behaviors.
class Behavior {
public:
    enum class Type {
        INPUT,
        OUTPUT,
        SLEEP,
        LAST
    };

    virtual ~Behavior() = default;
    Behavior::Type getType() const { return m_type; }

protected:
    explicit Behavior(Behavior::Type type) : m_type(type) {}

private:
    Behavior::Type m_type;
};


// read(), scanf(), gets(), fgets(), etc
class InputBehavior : public Behavior {
public:
    InputBehavior() : Behavior(Behavior::Type::INPUT) {}
    virtual ~InputBehavior() = default;
};


// write(), printf(), puts(), fputs(), etc
class OutputBehavior : public Behavior {
public:
    OutputBehavior() : Behavior(Behavior::Type::OUTPUT) {}
    virtual ~OutputBehavior() = default;
};


// sleep()
class SleepBehavior : public Behavior {
public:
    explicit SleepBehavior(uint64_t interval)
        : Behavior(Behavior::Type::SLEEP),
          m_interval(interval) {}
    virtual ~SleepBehavior() = default;

    uint64_t getInterval() const { return m_interval; }

private:
    uint64_t m_interval;
};

}  // namespace s2e::plugins::requiem

#endif  // S2E_PLUGINS_REQUIEM_BEHAVIORS_H
