#pragma once

#include <cstdint>

#ifndef TRACKING_ALLOCATOR_API
#define TRACKING_ALLOCATOR_API
#endif
#ifndef TRACKING_ALLOCATOR_NAMESPACE
#define TRACKING_ALLOCATOR_NAMESPACE tracking
#endif

namespace TRACKING_ALLOCATOR_NAMESPACE
{

// tracks allocations to locate memory leaks
struct TRACKING_ALLOCATOR_API TrackingAllocator
{
    static void* alloc(size_t size);
    static void free(void* mem);
    static void* aligned_alloc(size_t size, size_t alignment);
    static void aligned_free(void* mem);
};

}
