#pragma once

#include <cstdint>

#ifndef TRACKING_ALLOCATOR_HAS_MUTEX_TYPE
#define TRACKING_ALLOCATOR_HAS_MUTEX_TYPE
#include <mutex>
using Mutex = std::mutex;
using ScopedLock = std::lock_guard<std::mutex>;
#define TRACKING_ALLOCATOR_MUTEX_LOCK_FUNC lock
#define TRACKING_ALLOCATOR_MUTEX_UNLOCK_FUNC unlock
#endif

#ifndef TRACKING_ALLOCATOR_API
#define TRACKING_ALLOCATOR_API
#endif

#ifndef TRACKING_ALLOCATOR_NAMESPACE
#define TRACKING_ALLOCATOR_NAMESPACE tracking
#endif

#ifndef TRACKING_ALLOCATOR_HAS_SPAN_TYPE
#define TRACKING_ALLOCATOR_HAS_SPAN_TYPE
#include <span>
template<typename T>
using Span = std::span<T>;
#endif

#ifndef TRACKING_ALLOCATOR_ASSERT
#define TRACKING_ALLOCATOR_ASSERT
#endif

namespace TRACKING_ALLOCATOR_NAMESPACE
{

// tracks allocations to locate memory leaks
struct TrackingAllocator
{
    static void* alloc(size_t size);
    static void free(void* mem);
    static void* aligned_alloc(size_t size, size_t alignment);
    static void aligned_free(void* mem);
};

}
