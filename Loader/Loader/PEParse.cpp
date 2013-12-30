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
