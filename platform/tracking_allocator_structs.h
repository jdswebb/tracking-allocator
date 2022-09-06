namespace TRACKING_ALLOCATOR_NAMESPACE
{

struct StackNode;

struct StackTree
{
public:
	StackTree();
	~StackTree();

	StackNode* record();
	void printCallstack(StackNode* node);
	static bool getFunction(StackNode* node, Span<char> out, int& line);
	static StackNode* getParent(StackNode* node);
	static int getPath(StackNode* node, Span<StackNode*> output);
	static void refreshModuleList();

private:
	StackNode* insertChildren(StackNode* node, void** instruction, void** stack);

private:
	StackNode* m_root;
};

struct Allocator final
{
public:
	struct AllocationInfo
	{
		AllocationInfo* previous;
		AllocationInfo* next;
		size_t size;
		StackNode* stack_leaf;
		uint16_t align;
	};

public:
	explicit Allocator();
	~Allocator();

	void* allocate(size_t size);
	void deallocate(void* ptr);
	void* allocate_aligned(size_t size, size_t align);
	void deallocate_aligned(void* ptr);
	size_t getTotalSize() const { return m_total_size; }
	void checkGuards();
	void checkLeaks();

	AllocationInfo* getFirstAllocationInfo() const { return m_root; }
	void lock();
	void unlock();

private:
	inline size_t getAllocationOffset();
	inline AllocationInfo* getAllocationInfoFromSystem(void* system_ptr);
	inline AllocationInfo* getAllocationInfoFromUser(void* user_ptr);
	inline uint8_t* getUserFromSystem(void* system_ptr, size_t align);
	inline uint8_t* getSystemFromUser(void* user_ptr);
	inline size_t getNeededMemory(size_t size);
	inline size_t getNeededMemory(size_t size, size_t align);
	inline void* getUserPtrFromAllocationInfo(AllocationInfo* info);

private:
	StackTree m_stack_tree;
	Mutex m_mutex;
	AllocationInfo* m_root;
	AllocationInfo m_sentinels[2];
	size_t m_total_size;
	bool m_is_fill_enabled;
	bool m_are_guards_enabled;
};

}