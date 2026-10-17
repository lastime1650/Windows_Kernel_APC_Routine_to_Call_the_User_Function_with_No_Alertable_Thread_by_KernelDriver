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
		return RegisterUserApc(
			(HANDLE)15652, // Target PID 
			(HANDLE)6764,  // Target TID
			(PVOID)0x00007FF69FF817D0, // Normal Routine Address 
			(PVOID)0x0, // Normal Routine Context
			0x0, // Normal Routine SystemParameter 1
			0x0  // Normal Routine SystemParameter 2
		);
	}
}