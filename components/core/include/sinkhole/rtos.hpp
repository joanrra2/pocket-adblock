#pragma once
// Thin, allocation-free wrappers over FreeRTOS static primitives.

#include <cstddef>
#include <cstdint>

#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "freertos/task.h"

namespace sinkhole {

// Task whose stack and TCB live inside the owning object (no heap).
// ESP-IDF's FreeRTOS takes stack sizes in bytes and StackType_t is a byte.
template <size_t StackBytes>
class StaticTask {
public:
    bool start(const char* name, TaskFunction_t fn, void* arg, UBaseType_t prio)
    {
        handle_ = xTaskCreateStatic(fn, name, StackBytes, arg, prio, stack_, &tcb_);
        return handle_ != nullptr;
    }
    TaskHandle_t handle() const { return handle_; }
    void notify() const
    {
        if (handle_) xTaskNotifyGive(handle_);
    }

private:
    alignas(16) StackType_t stack_[StackBytes];
    StaticTask_t tcb_{};
    TaskHandle_t handle_ = nullptr;
};

// Mutex with static storage. Must be constructed after the scheduler starts
// (all owners are members of the App object built in app_main).
class Mutex {
public:
    Mutex() : h_(xSemaphoreCreateMutexStatic(&buf_)) {}
    Mutex(const Mutex&) = delete;
    Mutex& operator=(const Mutex&) = delete;
    void lock() { xSemaphoreTake(h_, portMAX_DELAY); }
    void unlock() { xSemaphoreGive(h_); }

private:
    StaticSemaphore_t buf_{};
    SemaphoreHandle_t h_;
};

class LockGuard {
public:
    explicit LockGuard(Mutex& m) : m_(m) { m_.lock(); }
    ~LockGuard() { m_.unlock(); }
    LockGuard(const LockGuard&) = delete;
    LockGuard& operator=(const LockGuard&) = delete;

private:
    Mutex& m_;
};

inline uint32_t uptimeSeconds()
{
    return static_cast<uint32_t>(xTaskGetTickCount() / configTICK_RATE_HZ);
}

}  // namespace sinkhole
