#include <Windows.h>


class PEParse
{
public:
	PEParse( WCHAR * FileName );
	PEParse( CHAR * FileName );

	~PEParse(void);

	BOOL ParseFile();

	// ��ȡpeͷ
	PIMAGE_DOS_HEADER		GetImgDosHeader();
	// ��ȡntͷ
	PIMAGE_NT_HEADERS		GetImgNtHeader();
	
	// ��ȡxx��
	PIMAGE_DATA_DIRECTORY	GetImgDataDirectory( DWORD DataIndex );
	
	

	// �޸������
	BOOL BuildImgImportTable();
	
	//�޸�TLS��
	BOOL BuildImgTLSTable();
	
	// ����������������������Ҫ��һ���������ɰܾ�������������ˡ�
	BOOL GetImgModuleHandle();
	
private:
	PIMAGE_DOS_HEADER pImgDosHeader;
	PIMAGE_NT_HEADERS pImgNtHeader;
	
	LPBYTE PeFile;
	LPBYTE HModule;
};
