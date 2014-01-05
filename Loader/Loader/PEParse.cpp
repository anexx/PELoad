#include "PEParse.h"
#include <stdio.h>



PEParse::PEParse( CHAR *FileName ):PeFile(NULL), HModule(NULL), pImgNtHeader(NULL),NtAllocateVirtualMemory(NULL)
{
	HANDLE hFile = CreateFileA(FileName, FILE_READ_DATA, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if ( hFile == INVALID_HANDLE_VALUE )
		return;

	ReadPEFile( hFile );

	CloseHandle( hFile );

	InitDymlicFunction();
}

PEParse::~PEParse()
{
	if ( PeFile != NULL )
		VirtualFree( PeFile, 0, MEM_RELEASE );
	if ( HModule != NULL )
		VirtualFree( HModule, 0, MEM_RELEASE );
}

BOOL PEParse::ReadPEFile( HANDLE hFile )
{
	DWORD fileSize = GetFileSize( hFile, NULL );
	if (fileSize == 0 )
		return FALSE;

	PeFile = (LPBYTE)VirtualAlloc( NULL, fileSize, MEM_COMMIT, PAGE_READWRITE );
	if ( PeFile == NULL )
		return FALSE;

	return ReadFile(hFile, PeFile, fileSize, &fileSize, NULL );
}


PIMAGE_DOS_HEADER PEParse::GetImgDosHeader()
{
	if ( PeFile == NULL )
		return NULL;

	pImgDosHeader = ( PIMAGE_DOS_HEADER )PeFile;

	return pImgDosHeader;
}

PIMAGE_NT_HEADERS PEParse::GetImgNtHeader()
{
	if ( pImgDosHeader == NULL )
		return FALSE;

	if ( pImgDosHeader->e_magic != IMAGE_DOS_SIGNATURE )
		return NULL;

	pImgNtHeader = (PIMAGE_NT_HEADERS)( PeFile + pImgDosHeader->e_lfanew );

	return pImgNtHeader;
}

DWORD PEParse::GetImgSize()
{
	if ( pImgNtHeader->Signature != IMAGE_NT_SIGNATURE )
		return 0;

	return pImgNtHeader->OptionalHeader.SizeOfImage;
}

DWORD PEParse::GetImgBase()
{
	if ( pImgNtHeader == NULL )
		return 0;

	if ( pImgNtHeader->Signature != IMAGE_NT_SIGNATURE )
		return 0;

	return pImgNtHeader->OptionalHeader.ImageBase;
}
#define NT_SUCCESS(Status) ((NTSTATUS)(Status) >= 0)

BOOL PEParse::BuildImg()
{
	DWORD imgSize = GetImgSize();
	NTSTATUS status = 0;
	if ( imgSize == 0 )
		return FALSE;


	DWORD ImgBase = GetImgBase();
	if ( ImgBase == 0 )
		return FALSE;
	printf("Img Base = %X Size= %X\n", ImgBase, imgSize);
	if ( CheckNeedReloc() )
		// 如果有重定位段 ，可以在任意地址上申请数据
		HModule = (LPBYTE) VirtualAlloc( NULL, imgSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE );
	else { 
		//HModule = (LPBYTE)ImgBase;
		// 否则，就表示没有重定位段。那么就只能在指定的位置上申请内存了，不然就over了。
		//status = NtAllocateVirtualMemory( GetCurrentProcess(),(LPVOID*)&HModule,0, &imgSize, MEM_COMMIT|MEM_RESERVE|MEM_TOP_DOWN, PAGE_EXECUTE_READWRITE );
// 		
// 		printf("status = %X imgSize =%X\n", status, imgSize );
// 		if ( NT_SUCCESS(status)){
// 					return FALSE;
// 		}
		 
		HModule = (LPBYTE)VirtualAlloc(( LPVOID )ImgBase, imgSize,MEM_COMMIT|MEM_RESERVE|MEM_TOP_DOWN, PAGE_EXECUTE_READWRITE );
		//HModule = (LPBYTE)VirtualAlloc(( LPVOID )ImgBase, imgSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE );

	}
	if (HModule == NULL ){
		printf("BuildImg Failed\n");
		return FALSE;
	}
	return TRUE;
}

BOOL PEParse::BuildImgImportTable()
{
	PIMAGE_DATA_DIRECTORY pImageDataDirectory = &pImgNtHeader->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_IMPORT ];
	if ( pImageDataDirectory->Size == 0 )
		return TRUE;
	
	PIMAGE_IMPORT_BY_NAME		pImgImportByName		= NULL ;
	PIMAGE_IMPORT_DESCRIPTOR	pImgImportDescriptor	= NULL ;
	
	DWORD	*thunkRef	= NULL;
	FARPROC	*funcRef	= NULL;
	HMODULE	DllModule	= NULL;

	pImgImportDescriptor = ( PIMAGE_IMPORT_DESCRIPTOR )(HModule + pImageDataDirectory->VirtualAddress );

	for (;!IsBadReadPtr( pImgImportDescriptor, sizeof (IMAGE_IMPORT_DESCRIPTOR)) && pImgImportDescriptor->Name; pImgImportDescriptor ++ )
	{
		DllModule =LoadLibraryA((LPCSTR)HModule + pImgImportDescriptor->Name );
		if (DllModule == NULL ){
			printf("Load Library Failed%s\n",(LPCSTR)HModule + pImgImportDescriptor->Name );
			return FALSE;
		}

		if ( pImgImportDescriptor->OriginalFirstThunk ){
			thunkRef = ( DWORD *)(HModule + pImgImportDescriptor->OriginalFirstThunk );
		} else {
			thunkRef = ( DWORD *)(HModule + pImgImportDescriptor->FirstThunk );
		}
		funcRef = (FARPROC *)(HModule + pImgImportDescriptor->FirstThunk );

		for ( ; *thunkRef; thunkRef ++, funcRef ++) {
			if ( IMAGE_SNAP_BY_ORDINAL(*thunkRef ) ){
				*funcRef = (FARPROC )GetProcAddress(DllModule, (LPCSTR)IMAGE_ORDINAL(*thunkRef ));
			}else {
				pImgImportByName = ( PIMAGE_IMPORT_BY_NAME )(HModule + (*thunkRef) );
				*funcRef = (FARPROC)GetProcAddress(DllModule, (LPCSTR)&pImgImportByName->Name );
			}

			if (* funcRef == NULL ){
				printf( "GetFuncAddress %s\n failed\n", &pImgImportByName->Name ); // 这里注意，并不一定是name导入的，所以有可能会在这里崩溃的。
 				break;
			}
		}
	}

	return TRUE;
}

BOOL PEParse::BuildImgTLSTable()
{
	return FALSE;
}

// 这里要注意了，如果没有将文件头copy过去的话，整个数据将要出错的。这个真的是一个悲剧啊。。。
// fuck
BOOL PEParse::CopySections()
{
	PIMAGE_SECTION_HEADER pImgSectionHeader = NULL;

	WORD sectionCount = pImgNtHeader->FileHeader.NumberOfSections;
	if ( sectionCount == 0 )
		return TRUE;
	
	pImgSectionHeader = ( PIMAGE_SECTION_HEADER )( pImgNtHeader + 1);
	
	// 首先copy FileHeader
	memcpy_s( HModule, sizeof (IMAGE_DOS_HEADER), pImgDosHeader, sizeof (IMAGE_DOS_HEADER));
	
	// 接着copy Ntheader
	memcpy_s( HModule + pImgDosHeader->e_lfanew, sizeof (IMAGE_NT_HEADERS), pImgNtHeader, sizeof (IMAGE_NT_HEADERS));
	
	LPBYTE OffSet = (HModule + pImgDosHeader->e_lfanew + sizeof (IMAGE_NT_HEADERS));

	// 这里不能只拷贝数据段，同时要把名称也要拷贝过去的
	for ( WORD index = 0; index < sectionCount; index ++)
	{
		printf("Section Name = %s Address = %X\n", pImgSectionHeader->Name, pImgSectionHeader->VirtualAddress);
		memcpy_s( OffSet, sizeof (IMAGE_SECTION_HEADER), pImgSectionHeader, sizeof (PIMAGE_SECTION_HEADER));
		memcpy_s( HModule + pImgSectionHeader->VirtualAddress, pImgSectionHeader->SizeOfRawData, PeFile+ pImgSectionHeader->PointerToRawData, pImgSectionHeader->SizeOfRawData);
		pImgSectionHeader ++;
	}

	return TRUE;
}

BOOL PEParse::JmpToEngtryPoint()
{
	DWORD EntryPoint = pImgNtHeader->OptionalHeader.AddressOfEntryPoint;
	typedef void (__cdecl *PFNEntryPointFunction)(void);
	
	if ( EntryPoint == 0 )
		return FALSE;

	PFNEntryPointFunction pfnEntryPointFunction = (PFNEntryPointFunction)(HModule + EntryPoint);
	
	// 这个地方是通过这种方式来捕获异常。
	try{
		__asm int 3
		pfnEntryPointFunction();
	}
	catch(...)
	{
		return FALSE;
	}

	return TRUE;
}

BOOL PEParse::BuildRealocTable()
{
	if ( !CheckNeedReloc() )
		return TRUE;

	PIMAGE_DATA_DIRECTORY pImgDataDirectory = &pImgNtHeader->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_BASERELOC];	
	PIMAGE_BASE_RELOCATION  pImgBaseRelocation = ( PIMAGE_BASE_RELOCATION )(HModule + pImgDataDirectory->VirtualAddress );
	
	DWORD index = 0 ;
	DWORD *patchAddr = NULL;
	DWORD relocType  = 0;
	DWORD offset	 = 0;
	unsigned short * relocaInfo = NULL;
	for (; pImgBaseRelocation->VirtualAddress > 0; )
	{
		relocaInfo = (unsigned short *)((unsigned char *)pImgBaseRelocation + sizeof ( IMAGE_BASE_RELOCATION));

		for (index = 0; index < (pImgBaseRelocation->SizeOfBlock - sizeof (IMAGE_BASE_RELOCATION) )/2; index ++, relocaInfo ++ )
		{
			relocType	= *relocaInfo >> 12;
			offset		= *relocaInfo &0xfff;
			switch ( relocType )
			{
			case IMAGE_REL_BASED_ABSOLUTE:
				break;

			case IMAGE_REL_BASED_HIGHLOW:
				patchAddr = (DWORD *)(HModule + pImgBaseRelocation->VirtualAddress + offset);
				*patchAddr += (DWORD_PTR)( HModule -pImgNtHeader->OptionalHeader.ImageBase );
				break;

			case IMAGE_REL_BASED_DIR64:
				break;
			}
			
		}
		pImgBaseRelocation = (PIMAGE_BASE_RELOCATION)((UCHAR*)pImgBaseRelocation + pImgBaseRelocation->SizeOfBlock );
	}

	return TRUE;
}

// 这种检查方法能行不？
BOOL PEParse::CheckNeedReloc()
{
	return pImgNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size != 0;
}

BOOL PEParse::CheckNeedImport()
{
	return pImgNtHeader->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_IMPORT].Size != 0;
}

BOOL PEParse::CheckNeedResource()
{
	return pImgNtHeader->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_RESOURCE].Size !=0 ;
}

BOOL PEParse::ParseFile()
{
	if ( PeFile == NULL )return FALSE;

	if ( GetImgDosHeader() == NULL )return FALSE;
	if ( GetImgNtHeader() == NULL )return FALSE;
	if ( BuildImg() == FALSE )return FALSE;
	if ( CopySections() == FALSE)return FALSE;
	if ( BuildRealocTable() == FALSE ) return FALSE;

	if ( BuildImgImportTable() == FALSE )return FALSE;

	if (JmpToEngtryPoint() == FALSE)return FALSE;

	return TRUE;
}


BOOL PEParse::InitDymlicFunction()
{
	NtAllocateVirtualMemory = (PFNNtAllocateVirtualMemory)GetProcAddress(GetModuleHandleA("ntdll.dll"),"NtAllocateVirtualMemory");
	return NtAllocateVirtualMemory != NULL;
}