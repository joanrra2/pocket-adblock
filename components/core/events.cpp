#include "sinkhole/events.hpp"

#include <array>
#include <atomic>
#include <cstdarg>
#include <cstdio>

namespace sinkhole::events {

namespace {
std::atomic<Sink>& sink()
{
    static std::atomic<Sink> s{nullptr};
    return s;
}
}  // namespace

void setSink(Sink s)
{
    sink().store(s);
}

bool active()
{
    return sink().load() != nullptr;
}

void emit(Kind kind, const char* fmt, ...)
{
    const Sink s = sink().load();
    if (!s) return;
    std::array<char, 161> text;
    va_list args;
    va_start(args, fmt);
    vsnprintf(text.data(), text.size(), fmt, args);  // NOSONAR printf-style API, format checked by the compiler
    va_end(args);
    s(kind, text.data());
}

}  // namespace sinkhole::events
