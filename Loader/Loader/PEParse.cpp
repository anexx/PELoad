#include "PEParse.h"

PEParse::PEParse( WCHAR *FileName ):PeFile(NULL), HModule(NULL), pImgNtHeader(NULL), pImgNtHeader(NULL)
{
	HANDLE hFile = CreateFileW(FileName, FILE_READ_DATA, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE )
		return;
	ReadPEFile( hFile );
	CloseHandle( hFile );
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
	PeFile = VirtualAlloc( NULL, fileSize, MEM_COMMIT, PAGE_READWRITE );
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


BOOL PEParse::BuildImg()
{
	DWORD imgSize = GetImgSize();
	
	if ( imgSize == 0 )
		return FALSE;


	DWORD ImgBase = GetImgBase();
	if ( ImgBase == 0 )
		return FALSE;

	HModule = (LPBYTE) VirtualAlloc( ImgBase, imgSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE );
	
	if ( HModule == NULL )
		HModule = VirtualAlloc( ImgBase, ImgBase, MEM_COMMIT, PAGE_EXECUTE_READWRITE );

	if ( HModule == NULL )
		return FALSE;
}

BOOL PEParse::BuildImgImportTable()
{
	PIMAGE_DATA_DIRECTORY pImageDataDirectory = pImgNtHeader->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_IMPORT ];
	if ( pImageDataDirectory->Size == 0 )
		return TRUE;
	
	PIMAGE_IMPORT_BY_NAME		pImgImportByName		= NULL;
	PIMAGE_IMPORT_DESCRIPTOR	pImgImportDescriptor	= NULL;

	return FALSE;
}

BOOL PEParse::BuildImgTLSTable()
{
	return FALSE;
}


BOOL PEParse::CopySections()
{
	PIMAGE_SECTION_HEADER pImgSectionHeader = NULL;

	WORD sectionCount = pImgNtHeader->FileHeader.NumberOfSections;
	if ( sectionCount == 0 )
		return TRUE;
	
	pImgSectionHeader = (PIMAGE_SECTION_HEADER)( pImgNtHeader + 1);
	for ( WORD index = 0; index < sectionCount; index ++)
	{
		memcpy_s( HModule + pImgSectionHeader->VirtualAddress, pImgSectionHeader->SizeOfRawData, PeFile+ pImgSectionHeader->PointerToRawData, pImgSectionHeader->SizeOfRawData);
		pImgSectionHeader ++;
	}

	return TRUE;
}

BOOL PEParse::JmpToEngtryPoint()
{
	DWORD EntryPoint = pImgNtHeader->OptionalHeader.AddressOfEntryPoint;
	typedef void (__cdecl PFNEntryPointFunction)(void);
	
	if ( EntryPoint == 0 )
		return FALSE;

	PFNEntryPointFunction pfnEntryPointFunction = (PFNEntryPointFunction)(HModule + EntryPoint);

	// 这个地方来抓所有的错误信息，但是不知道能不能行呢。
	try{
		pfnEntryPointFunction();
	}
	catch(...)
	{
		return FALSE;
	}

	return TRUE;
}

