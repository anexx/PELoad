#include <Windows.h>

typedef NTSTATUS (WINAPI *PFNNtAllocateVirtualMemory)( HANDLE ,  LPVOID * BaseAddress, ULONG ZeroBit, PULONG RegionSize, ULONG AllocType, ULONG ProtectType );

class PEParse
{
public:
	PEParse( CHAR * FileName );

	~PEParse(void);

	BOOL ParseFile();

	// 获取pe头
	PIMAGE_DOS_HEADER		GetImgDosHeader();
	// 获取nt头
	PIMAGE_NT_HEADERS		GetImgNtHeader();

	// 修复导入表
	BOOL BuildImgImportTable();

	//修复TLS表
	BOOL BuildImgTLSTable();

	// 这个函数是这个工程中最重要的一个函数，成败就在这个函数上了。
	BOOL GetImgModuleHandle();

	BOOL CopySections();

	// 跳入到代码入口处执行
	BOOL JmpToEngtryPoint();

	// 修复重定位段
	BOOL BuildRealocTable();

	// 检查是否需要重定位，如果没有重定位，
	// 则要返回错误
	BOOL CheckNeedReloc();
	
	BOOL CheckNeedImport();

	BOOL CheckNeedResource();

private:

	// 获取镜像大小
	DWORD GetImgSize();

	// 获取镜像基质
	DWORD GetImgBase();

	// 获取pe文件数据
	BOOL ReadPEFile( HANDLE hFile );

	// 这个函数实际是构造pe文件的内存基址。
	BOOL BuildImg();	

	BOOL InitDymlicFunction();


private:
	PIMAGE_DOS_HEADER pImgDosHeader;
	PIMAGE_NT_HEADERS pImgNtHeader;
	
	LPBYTE PeFile;
	LPBYTE HModule;

	PFNNtAllocateVirtualMemory  NtAllocateVirtualMemory;
};
