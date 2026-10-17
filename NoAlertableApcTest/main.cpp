#include "apc.hpp"


extern "C" {
	NTSTATUS DriverEntry(
		PUNICODE_STRING a1,
		PDRIVER_OBJECT a2
	)
	{
		UNREFERENCED_PARAMETER(a1);
		UNREFERENCED_PARAMETER(a2);
		// Direct TEST
		return RegisterUserApc((HANDLE)25468, (HANDLE)23060, (PVOID)0x00007FF6540617D0);
	}
}