#include "PEParse.h"
#include <stdio.h>


int main(int argc, char ** argv )
{
	SYSTEM_INFO sysInfo;
	GetSystemInfo(&sysInfo);

	DWORD Lower = (DWORD)sysInfo.lpMinimumApplicationAddress;
	DWORD Max	= (DWORD)sysInfo.lpMaximumApplicationAddress;
	 
	DWORD Ptr = 0x400000;
	MEMORY_BASIC_INFORMATION memInfo;
	
	if ( VirtualQuery((LPVOID)Ptr, &memInfo, sizeof (memInfo)) ==0 )
		return 0;
		
	//	printf("\t %08X : %08X - %08X", m)
		printf("baseAddress = %X\n", memInfo.BaseAddress);
		printf("AllocateBase = %X\n", memInfo.AllocationBase);
		printf("AllocatProterct = %X\n", memInfo.AllocationProtect);
		printf("RegionSize = %X\n", memInfo.RegionSize);
		printf("State = %X\n", memInfo.State);
		printf("Protect = %X\n", memInfo.Protect);
		printf("Type = %X\n", memInfo.Type);
		
		//printf("allcoate address = %x ,%X\n", VirtualAlloc((LPVOID)0x00400000, 0x8c00, MEM_COMMIT, PAGE_READWRITE), GetLastError());
		
		LPVOID  Buffer = VirtualAlloc((LPVOID)0x00400000, 0x8700,MEM_COMMIT,PAGE_READWRITE);
		
		printf("%X:%d\n",Buffer, GetLastError());
// 	if ( argc < 2 ){
// 		printf("usage %s exefileName", argv[0]);
// 		return 0;
// 	}	
// 
// 	PEParse *peParse = new PEParse( argv[1]);
// 
// 	peParse->ParseFile();
}