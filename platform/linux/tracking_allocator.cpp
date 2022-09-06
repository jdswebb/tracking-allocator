#include "tracking_allocator.h"
#include "platform/tracking_allocator_structs.h"
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <execinfo.h>

#define ENABLE_TRACKING

namespace TRACKING_ALLOCATOR_NAMESPACE
{
struct NewPlaceholder {};
}
inline void* operator new(size_t, TRACKING_ALLOCATOR_NAMESPACE::NewPlaceholder, void* where) { return where; }
inline void operator delete(void*, TRACKING_ALLOCATOR_NAMESPACE::NewPlaceholder, void*) { }

namespace TRACKING_ALLOCATOR_NAMESPACE
{


struct StackNode
{
	~StackNode()
	{
        ::free(m_next);
        ::free(m_first_child);
	}

	void* m_instruction;
	StackNode* m_next;
	StackNode* m_first_child;
	StackNode* m_parent;
};


StackTree::StackTree()
	: m_root(nullptr)
{}

StackTree::~StackTree()
{
    ::free(m_root);
}

void StackTree::refreshModuleList() {}


int StackTree::getPath(StackNode* node, Span<StackNode*> output) {
	uint32_t i = 0;
	while (i < output.length() && node) {
		output[i] = node;
		i++;
		node = node->m_parent;
	}
	return i;
}


StackNode* StackTree::getParent(StackNode* node) {
	return node ? node->m_parent : nullptr;
}


bool StackTree::getFunction(StackNode* node, Span<char> out, int& line) {
	char** str = backtrace_symbols(&node->m_instruction, 1);
	if (!str) return false;

	strcpy(out, *str);
	free(str);
	line = -1;
	return true;
}


void StackTree::printCallstack(StackNode* node) {
	char** str = backtrace_symbols(&node->m_instruction, 1);
	if (str) {
		printf("%s", *str);
		free(str);
	}
}


StackNode* StackTree::insertChildren(StackNode* root_node, void** instruction, void** stack) {
	StackNode* node = root_node;
	while (instruction >= stack) {
		StackNode* new_node = (StackNode*)malloc(sizeof(StackNode));
		node->m_first_child = new_node;
		new_node->m_parent = node;
		new_node->m_next = nullptr;
		new_node->m_first_child = nullptr;
		new_node->m_instruction = *instruction;
		node = new_node;
		--instruction;
	}
	return node;
}

StackNode* StackTree::record() {
	static const int frames_to_capture = 256;
	void* stack[frames_to_capture];
	const int captured_frames_count = backtrace(stack, frames_to_capture);

	void** ptr = stack + captured_frames_count - 1;
	if (!m_root) {
		m_root = (StackNode*)malloc(sizeof(StackNode));
		m_root->m_instruction = *ptr;
		m_root->m_first_child = nullptr;
		m_root->m_next = nullptr;
		m_root->m_parent = nullptr;
		--ptr;
		return insertChildren(m_root, ptr, stack);
	}

	StackNode* node = m_root;
	while (ptr >= stack) {
		while (node->m_instruction != *ptr && node->m_next) {
			node = node->m_next;
		}
		if (node->m_instruction != *ptr) {
			node->m_next = (StackNode*)malloc(sizeof(StackNode));
			node->m_next->m_parent = node->m_parent;
			node->m_next->m_instruction = *ptr;
			node->m_next->m_next = nullptr;
			node->m_next->m_first_child = nullptr;
			--ptr;
			return insertChildren(node->m_next, ptr, stack);
		}

		if (node->m_first_child) {
			--ptr;
			node = node->m_first_child;
		} else if (ptr != stack) {
			--ptr;
			return insertChildren(node, ptr, stack);
		} else {
			return node;
		}
	}

	return node;
}

static const uint32_t UNINITIALIZED_MEMORY_PATTERN = 0xCD;
static const uint32_t FREED_MEMORY_PATTERN = 0xDD;
static const uint32_t ALLOCATION_GUARD = 0xFDFDFDFD;


TrackingAllocatorImpl::TrackingAllocatorImpl()
	: m_root(nullptr)
	, m_total_size(0)
	, m_is_fill_enabled(true)
	, m_are_guards_enabled(true) {
	m_sentinels[0].next = &m_sentinels[1];
	m_sentinels[0].previous = nullptr;
	m_sentinels[0].stack_leaf = nullptr;
	m_sentinels[0].size = 0;
	m_sentinels[0].align = 0;

	m_sentinels[1].next = nullptr;
	m_sentinels[1].previous = &m_sentinels[0];
	m_sentinels[1].stack_leaf = nullptr;
	m_sentinels[1].size = 0;
	m_sentinels[1].align = 0;

	m_root = &m_sentinels[1];
}


TrackingAllocatorImpl::~TrackingAllocatorImpl() {
	AllocationInfo* last_sentinel = &m_sentinels[1];
	if (m_root != last_sentinel) {
		debugOutput("Memory leaks detected!\n");
		AllocationInfo* info = m_root;
		while (info != last_sentinel) {
			char tmp[2048];
			sprintf(tmp, "\nAllocation size : %zu, memory %p\n", info->size, info + sizeof(info)); //-V568
			debugOutput(tmp);
			m_stack_tree.printCallstack(info->stack_leaf);
			info = info->next;
		}
		TRACKING_ALLOCATOR_ASSERT(false);
	}
}


void TrackingAllocatorImpl::lock() {
	m_mutex.TRACKING_ALLOCATOR_MUTEX_LOCK_FUNC();
}


void TrackingAllocatorImpl::unlock() {
	m_mutex.TRACKING_ALLOCATOR_MUTEX_UNLOCK_FUNC();
}


void TrackingAllocatorImpl::checkGuards() {
	if (m_are_guards_enabled) return;

	auto* info = m_root;
	while (info) {
		auto user_ptr = getUserPtrFromAllocationInfo(info);
		void* system_ptr = getSystemFromUser(user_ptr);
		TRACKING_ALLOCATOR_ASSERT(*(uint32_t*)system_ptr == ALLOCATION_GUARD);
		TRACKING_ALLOCATOR_ASSERT(*(uint32_t*)((uint8_t*)user_ptr + info->size) == ALLOCATION_GUARD);

		info = info->next;
	}
}


size_t TrackingAllocatorImpl::getAllocationOffset() {
	return sizeof(AllocationInfo) + (m_are_guards_enabled ? sizeof(ALLOCATION_GUARD) : 0);
}


size_t TrackingAllocatorImpl::getNeededMemory(size_t size) {
	return size + sizeof(AllocationInfo) + (m_are_guards_enabled ? sizeof(ALLOCATION_GUARD) << 1 : 0);
}


size_t TrackingAllocatorImpl::getNeededMemory(size_t size, size_t align) {
	return size + sizeof(AllocationInfo) + (m_are_guards_enabled ? sizeof(ALLOCATION_GUARD) << 1 : 0) + align;
}


TrackingAllocatorImpl::AllocationInfo* TrackingAllocatorImpl::getAllocationInfoFromSystem(void* system_ptr) {
	return (AllocationInfo*)(m_are_guards_enabled ? (uint8_t*)system_ptr + sizeof(ALLOCATION_GUARD) : system_ptr);
}


void* TrackingAllocatorImpl::getUserPtrFromAllocationInfo(AllocationInfo* info) {
	return ((uint8_t*)info + sizeof(AllocationInfo));
}


TrackingAllocatorImpl::AllocationInfo* TrackingAllocatorImpl::getAllocationInfoFromUser(void* user_ptr) {
	return (AllocationInfo*)((uint8_t*)user_ptr - sizeof(AllocationInfo));
}


uint8_t* TrackingAllocatorImpl::getUserFromSystem(void* system_ptr, size_t align) {
	size_t diff = (m_are_guards_enabled ? sizeof(ALLOCATION_GUARD) : 0) + sizeof(AllocationInfo);

	if (align) diff += (align - diff % align) % align;
	return (uint8_t*)system_ptr + diff;
}


uint8_t* TrackingAllocatorImpl::getSystemFromUser(void* user_ptr) {
	AllocationInfo* info = getAllocationInfoFromUser(user_ptr);
	size_t diff = (m_are_guards_enabled ? sizeof(ALLOCATION_GUARD) : 0) + sizeof(AllocationInfo);
	if (info->align) diff += (info->align - diff % info->align) % info->align;
	return (uint8_t*)user_ptr - diff;
}



void* TrackingAllocatorImpl::allocate_aligned(size_t size, size_t align) {
#ifndef ENABLE_TRACKING
	return m_source.allocate_aligned(size, align);
#else
	void* system_ptr;
	AllocationInfo* info;
	uint8_t* user_ptr;

	size_t system_size = getNeededMemory(size, align);
	{
		ScopedLock lock(m_mutex);
		system_ptr = ::aligned_alloc(system_size);
		user_ptr = getUserFromSystem(system_ptr, align);
		info = new (NewPlaceholder(), getAllocationInfoFromUser(user_ptr)) AllocationInfo();

		info->previous = m_root->previous;
		m_root->previous->next = info;

		info->next = m_root;
		m_root->previous = info;

		m_root = info;

		m_total_size += size;
	} // because of the MutexGuard

	info->align = uint16_t(align);
	info->stack_leaf = m_stack_tree.record();
	info->size = size;
	if (m_is_fill_enabled) {
		memset(user_ptr, UNINITIALIZED_MEMORY_PATTERN, size);
	}

	if (m_are_guards_enabled) {
		*(uint32_t*)system_ptr = ALLOCATION_GUARD;
		*(uint32_t*)((uint8_t*)system_ptr + system_size - sizeof(ALLOCATION_GUARD)) = ALLOCATION_GUARD;
	}

	return user_ptr;
#endif
}


void TrackingAllocatorImpl::deallocate_aligned(void* user_ptr) {
#ifndef ENABLE_TRACKING
	m_source.deallocate_aligned(user_ptr);
#else
	if (user_ptr) {
		AllocationInfo* info = getAllocationInfoFromUser(user_ptr);
		void* system_ptr = getSystemFromUser(user_ptr);
		if (m_is_fill_enabled) {
			memset(user_ptr, FREED_MEMORY_PATTERN, info->size);
		}

		if (m_are_guards_enabled) {
			TRACKING_ALLOCATOR_ASSERT(*(uint32_t*)system_ptr == ALLOCATION_GUARD);
			size_t system_size = getNeededMemory(info->size, info->align);
			TRACKING_ALLOCATOR_ASSERT(*(uint32_t*)((uint8_t*)system_ptr + system_size - sizeof(ALLOCATION_GUARD)) == ALLOCATION_GUARD);
		}

		{
			ScopedLock lock(m_mutex);
			if (info == m_root) {
				m_root = info->next;
			}
			info->previous->next = info->next;
			info->next->previous = info->previous;

			m_total_size -= info->size;
		} // because of the MutexGuard

		info->~AllocationInfo();

		::free((void*)system_ptr);
	}
#endif
}



void* TrackingAllocatorImpl::allocate(size_t size) {
#ifndef ENABLE_TRACKING
	return m_source.allocate(size);
#else
	void* system_ptr;
	AllocationInfo* info;
	size_t system_size = getNeededMemory(size);
	{
		ScopedLock lock(m_mutex);
		system_ptr = malloc(system_size);
		info = new (NewPlaceholder(), getAllocationInfoFromSystem(system_ptr)) AllocationInfo();

		info->previous = m_root->previous;
		m_root->previous->next = info;

		info->next = m_root;
		m_root->previous = info;

		m_root = info;

		m_total_size += size;
	} // because of the MutexGuard

	void* user_ptr = getUserFromSystem(system_ptr, 0);
	info->stack_leaf = m_stack_tree.record();
	info->size = size;
	info->align = 0;
	if (m_is_fill_enabled) {
		memset(user_ptr, UNINITIALIZED_MEMORY_PATTERN, size);
	}

	if (m_are_guards_enabled) {
		*(uint32_t*)system_ptr = ALLOCATION_GUARD;
		*(uint32_t*)((uint8_t*)system_ptr + system_size - sizeof(ALLOCATION_GUARD)) = ALLOCATION_GUARD;
	}

	return user_ptr;
#endif
}

void TrackingAllocatorImpl::deallocate(void* user_ptr) {
#ifndef ENABLE_TRACKING
	m_source.deallocate(user_ptr);
#else
	if (user_ptr) {
		AllocationInfo* info = getAllocationInfoFromUser(user_ptr);
		void* system_ptr = getSystemFromUser(user_ptr);
		if (m_is_fill_enabled) {
			memset(user_ptr, FREED_MEMORY_PATTERN, info->size);
		}

		if (m_are_guards_enabled) {
			TRACKING_ALLOCATOR_ASSERT(*(uint32_t*)system_ptr == ALLOCATION_GUARD);
			size_t system_size = getNeededMemory(info->size);
			TRACKING_ALLOCATOR_ASSERT(*(uint32_t*)((uint8_t*)system_ptr + system_size - sizeof(ALLOCATION_GUARD)) == ALLOCATION_GUARD);
		}

		{
			ScopedLock lock(m_mutex);
			if (info == m_root) {
				m_root = info->next;
			}
			info->previous->next = info->next;
			info->next->previous = info->previous;

			m_total_size -= info->size;
		} // because of the MutexGuard

		info->~AllocationInfo();

		::free((void*)system_ptr);
	}
#endif
}

TrackingAllocatorImpl g_tracking_allocator_impl_instance;

void* TrackingAllocator::alloc(size_t size)
{
    return g_tracking_allocator_impl_instance.allocate(size);
}

void TrackingAllocator::free(void* mem)
{
    g_tracking_allocator_impl_instance.deallocate(mem);
}

void* TrackingAllocator::aligned_alloc(size_t size, size_t alignment)
{
    return g_tracking_allocator_impl_instance.allocate_aligned(size, alignment);
}

void TrackingAllocator::aligned_free(void* mem)
{
    g_tracking_allocator_impl_instance.deallocate_aligned(mem);
}

}
