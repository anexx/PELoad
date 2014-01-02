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

	BOOL CopySections();

	// 跳入到代码入口处执行
	BOOL JmpToEngtryPoint();
private:

	// 获取镜像大小
	DWORD GetImgSize();
	
	// 获取镜像基质
	DWORD GetImgBase();

	// 获取pe文件数据
	BOOL ReadPEFile( HANDLE hFile );

	// 这个函数实际是构造pe文件的内存基址。
	BOOL BuildImg();	


private:
	PIMAGE_DOS_HEADER pImgDosHeader;
	PIMAGE_NT_HEADERS pImgNtHeader;
	
	LPBYTE PeFile;
	LPBYTE HModule;
};
