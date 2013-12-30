#include <Windows.h>


class PEParse
{
public:
	PEParse( WCHAR * FileName );
	PEParse( CHAR * FileName );

	~PEParse(void);

	BOOL ParseFile();

	// 获取pe头
	PIMAGE_DOS_HEADER		GetImgDosHeader();
	// 获取nt头
	PIMAGE_NT_HEADERS		GetImgNtHeader();
	
	// 获取xx表
	PIMAGE_DATA_DIRECTORY	GetImgDataDirectory( DWORD DataIndex );
	
	

	// 修复导入表
	BOOL BuildImgImportTable();
	
	//修复TLS表
	BOOL BuildImgTLSTable();
	
	// 这个函数是这个工程中最重要的一个函数，成败就在这个函数上了。
	BOOL GetImgModuleHandle();
	
private:
	PIMAGE_DOS_HEADER pImgDosHeader;
	PIMAGE_NT_HEADERS pImgNtHeader;
	
	LPBYTE PeFile;
	LPBYTE HModule;
};
