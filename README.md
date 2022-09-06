# Tracking Allocator
---------

Allocator for Windows/Linux that tracks memory allocations and reports on exit if there are any leaks.

The implementation is from [Lumix Engine](https://github.com/nem0/LumixEngine/tree/master/src), adapted to work without using custom containers/threading/string constructs. Some of the replacements can be customised with defines in `tracking_allocator.h`

## Usage

Include `tracking_allocator.h` and the appropriate `tracking_allocator.cpp` for the OS in your project.

For use in DLL, define `TRACKING_ALLOCATOR_API` appropriately.

## License

MIT
