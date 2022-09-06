# Tracking Allocator
---------

Allocator that tracks memory allocations and reports on exit if there are any leaks.

The implementation is adapted from Lumix Engine to work without using custom containers/threading/string constructs. Some of these can still be customised with defines in `tracking_allocator.h`