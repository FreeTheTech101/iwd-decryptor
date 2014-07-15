#include "StdInc.h"
#include "Hooking.h"
#include "Utils.h"
#include <list>
#include <time.h>
#include <winsock.h>
#include <dbghelp.h>
#include <shellapi.h>
#include <shlobj.h>
#include "Tool.h"

using namespace std;

#pragma comment(linker,"/FIXED /BASE:0x8000000")

void PatchMW2_Console();
void PatchMW2_CryptoFiles();

DWORD init1 = 0x42F0A0;
DWORD init2 = 0x4301B0;
DWORD init3 = 0x406D10;
DWORD init4 = 0x4D2280;
DWORD init5 = 0x47F390;
DWORD init6 = 0x420830;
DWORD init7 = 0x64A020;
DWORD init8 = 0x4E0FB0;
DWORD init9 = 0x60AD10;
DWORD init10 = 0x5196C0;
DWORD init11 = 0x4A62A0;
DWORD init12 = 0x429080;

bool loadedFastfiles = false;
bool dumping = false;
bool verify = false;
bool useEntryNames = false;

void ZoneBuild(char* toBuild);

list<string> sources;
string zoneToBuild;
string toDump;
int dumpType;
void dumpModel(char * name);

void doInit()
{
	__asm
	{
		call init1
		call init2
		push 0
		call init3
		add esp, 4
		call init4
		call init5
		call init6
		call init7
		call init8
		call init9
		call init10
		call init11
		call init12
	}
}

LONG WINAPI CustomUnhandledExceptionFilter(LPEXCEPTION_POINTERS ExceptionInfo)
{
	// step 1: write minidump
	static LPEXCEPTION_POINTERS exceptionData;

	exceptionData = ExceptionInfo;

	// create a temporary stack for these calls
	DWORD* tempStack = new DWORD[16000];
	static DWORD* origStack;

	__asm
	{
		mov origStack, esp
		mov esp, tempStack
		add esp, 0FA00h
		sub esp, 1000h // local stack space over here, sort of
	}

	char error[1024];
	char filename[MAX_PATH];
	__time64_t time;
	tm* ltime;

	_time64(&time);
	ltime = _localtime64(&time);
	strftime(filename, sizeof(filename) - 1, "IWD-Decryptor-%Y%m%d%H%M%S.dmp", ltime);
	_snprintf(error, sizeof(error) - 1, "A minidump has been written to %s.", filename);

	HANDLE hFile = CreateFile(filename, GENERIC_WRITE, FILE_SHARE_WRITE, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);

	if (hFile != INVALID_HANDLE_VALUE)
	{
		MINIDUMP_EXCEPTION_INFORMATION ex;
		memset(&ex, 0, sizeof(ex));
		ex.ThreadId = GetCurrentThreadId();
		ex.ExceptionPointers = exceptionData;
		ex.ClientPointers = FALSE;

		MiniDumpWriteDump(GetCurrentProcess(), GetCurrentProcessId(), hFile, MiniDumpNormal, &ex, NULL, NULL);		

		CloseHandle(hFile);
	}
	else
	{
		_snprintf(error, sizeof(error) - 1, "An error (0x%x) occurred during creating %s.", GetLastError(), filename);
	}

	Com_Error(true, "Fatal error (0x%08x) at 0x%08x.\n%s", ExceptionInfo->ExceptionRecord->ExceptionCode, ExceptionInfo->ExceptionRecord->ExceptionAddress, error);	

	__asm
	{
		mov esp, origStack
	}

	delete[] tempStack;

	return 0;
}

void dumpCryptoFile(char* name, const char* path)
{
	//int fh1;
	//long fileLength;

	char filename[512];
	char dir[512];
	sprintf(filename, "%s/%s/%s", "raw", path, name);

	GetCurrentDirectoryA(sizeof(dir), dir);
	strcat(dir, "/");
	strcat(dir, filename);
	*(strrchr(dir, '/')) = '\0';

	size_t strl = strlen(dir);

	for (size_t i = 0; i < strl; i++)
	{
		if (dir[i] == '/') dir[i] = '\\';
	}

	SHCreateDirectoryExA(NULL, dir, NULL);

	BYTE* buffer;
	int fh;
	size_t size = FS_FOpenFileRead(name, &fh, false);//FS_ReadFile(name, (void**)&buffer);

	if(!fh || !size)
		return;

	buffer = (BYTE*)malloc(size);
	memset(buffer, 0, size);

	FS_Read(buffer, size, fh);
	FS_FCloseFile(fh);

	FILE* fp = fopen(filename, "wb");
	fwrite(buffer, sizeof(BYTE), size, fp);
	fclose(fp);
	//FS_FreeFile(buffer);
	free(buffer);
}

dvar_t** fs_basepath = (dvar_t**)0x63D0CD4;

int FS_IsFileEncrypted(const char* filename);

char iwdFile[MAX_PATH];

void unpackIWD_do(const char* iwdname)
{
	strncpy(iwdFile, iwdname, sizeof(iwdFile));
	if(!FS_IsFileEncrypted(iwdFile))
	{
		printf("Given archive is not encrypted!\n");
		return;
	}

	char path[MAX_PATH];

	strncpy(path, va("%s\\%s\\%s", (*fs_basepath)->current.string, "main", iwdFile), MAX_PATH);

	pack_t* iwdHandle;

	printf("\nSearching archive '%s'...\n", iwdFile);

	searchpath_s* tempPath = fs_searchpaths;

	while(tempPath && tempPath->pack)
	{
		if(!strcmp(va("%s.iwd", tempPath->pack->pakBasename), iwdFile))
		{
			iwdHandle = tempPath->pack;
			printf("Archive found!\n");
			break;
		}
		
		tempPath = tempPath->next;
	}

	if(!iwdHandle)
	{
		printf("Archive not found. Forcing it to load...\n");
		iwdHandle = FS_LoadZipFile(path, iwdFile);
	}

	if(iwdHandle && iwdHandle->numfiles)
	{
		fileInPack_t* files = iwdHandle->buildBuffer;

		for(int i = 0; i < iwdHandle->numfiles; i++)
		{
			int percent = (100.0 / iwdHandle->numfiles) * i;
			printf("Extracting: %d%%\r", percent);

			dumpCryptoFile(files[i].name, iwdFile);
		}

		printf("Extracting: 100%% -> %s/%s\n", "raw", iwdFile);
	}
	else
	{
		printf("Error!\n");
	}
}

bool isValidBuffer(char* buffer)
{
	for(int i = 0;i<strlen(buffer);i++)
	{
		if(buffer[i] != ' ')
		{
			return true;
		}
	}

	return false;
}

HANDLE hstdout;
void printDone();

void RunTool()
{
	doInit();

	SetConsoleTextAttribute( hstdout, 0x0A );
	printf("\nEnter IWDs to decrypt (separated by spaces or 'all'):\n");
	SetConsoleTextAttribute( hstdout, 0x07 );

	char buffer[512];
	gets(buffer);

	if(!isValidBuffer(buffer))
	{
		ExitProcess(0);
	}

	auto files = explode(buffer, " ");

	if(!strcmp(files[0].c_str(), "all"))
	{
		searchpath_s* tempPath = fs_searchpaths;
		while(tempPath && tempPath->pack)
		{
			if(FS_IsFileEncrypted(tempPath->pack->pakBasename))
			{
				unpackIWD_do(va("%s.iwd", tempPath->pack->pakBasename));
			}

			tempPath = tempPath->next;
		}
	}
	else
	{
		for(int i = 0; i < files.size(); i++)
		{
			unpackIWD_do(files[i].c_str());
		}
	}

	printDone();
}

void printDone()
{
	printf("\nPress any key to exit...");
	_getch();
	ExitProcess(0);
}

void printTitle(byte color)
{
	SetConsoleTextAttribute( hstdout, (color << 4) );
	printf("                                                                                 ");    SetConsoleTextAttribute( hstdout, color );
	printf("                                                                              ");       SetConsoleTextAttribute( hstdout, (color << 4) );
	printf("  ");                                                                                   SetConsoleTextAttribute( hstdout, color );
	printf("                      React's IWD Decryptor by momo5502                       ");       SetConsoleTextAttribute( hstdout, (color << 4) );
	printf("  ");                                                                                   SetConsoleTextAttribute( hstdout, color );
	printf("                                                                              ");       SetConsoleTextAttribute( hstdout, (color << 4) );
	printf("                                                                                 \n");  SetConsoleTextAttribute( hstdout, 0x07 );
}

void InitBridge()
{
	hstdout = GetStdHandle( STD_OUTPUT_HANDLE );
	SetConsoleTitle("IWD Decryptor");
	printTitle(11);

	// check version
	if (strcmp((char*)0x6E9638, "177"))
	{
		printf("Error loading IW4!\n");
		TerminateProcess(GetCurrentProcess(), 0);
	}

	PatchMW2_Console(); // redirect output
	PatchMW2_CryptoFiles(); // let us pull from iw4c fastfiles

	// add our entry point
	call(0x6BABA1, RunTool, PATCH_CALL);
	//call(0x5BCA85, CheckZoneLoad, PATCH_CALL);

	// fuck exceptions
	memset((DWORD*)0x6114B1, 0x90, 10);

	// always enable system console, not just if generating reflection probes
	memset((void*)0x60BB58, 0x90, 11);

	// disable 'ignoring asset' notices
	memset((void*)0x5BB902, 0x90, 5);

	// ignore 'no iwd files found in main'
	memset((void*)0x642A4B, 0x90, 5);

	// disable safe mode ish
	memset((void*)0x451434, 0x90, 5);

	// disable optimal options dialog
	memset((void*)0x450063, 0x90, 5);

	// exceptions
	SetUnhandledExceptionFilter(&CustomUnhandledExceptionFilter);

// 	// Causes chrashes somewhere in FS_Startup
// 	nop(0x482542, 5);
// 
// 	// Ignore fileSysCheck whatever
// 	*(BYTE*)0x4290DF = 0xEB;

	// allow loading of IWffu (unsigned) files
	*(BYTE*)0x4158D9 = 0xEB; // main function
	*(WORD*)0x4A1D97 = 0x9090; // DB_AuthLoad_InflateInit

	// NTA patches
	*(DWORD*)0x1CDE7FC = GetCurrentThreadId(); // patch main thread ID
	*(BYTE*)0x519DDF = 0; //r_loadForrenderer = 0 
	*(BYTE*)0x4CF7F0 = 0xCC; // dirty disk breakpoint
	*(BYTE*)0x51F450 = 0xC3; //r_delayloadimage retn
	*(BYTE*)0x51F03D = 0xEB; // image release jmp

	// basic checks (hash jumps, both normal and playlist)
	*(WORD*)0x5B97A3 = 0x9090;
	*(WORD*)0x5BA493 = 0x9090;

	*(WORD*)0x5B991C = 0x9090;
	*(WORD*)0x5BA60C = 0x9090;

	*(WORD*)0x5B97B4 = 0x9090;
	*(WORD*)0x5BA4A4 = 0x9090;

	// some other, unknown, check
	*(BYTE*)0x5B9912 = 0xB8;
	*(DWORD*)0x5B9913 = 1;

	*(BYTE*)0x5BA602 = 0xB8;
	*(DWORD*)0x5BA603 = 1;

	*(BYTE*)0x54ADB0 = 0xC3;
	*(BYTE*)0x647781 = 0xEB;

	memset((void *)0x51F4FA, 0x90, 6);
	memset((void *)0x505AFB, 0x90, 7);
	memset((void *)0x505BDB, 0x90, 7);
	memset((void *)0x51E5CB, 0x90, 5);

	// fs_basegame
	//*(DWORD*)0x6431D1 = (DWORD)"main";

	// r_registerDvars hack
	*(BYTE*)0x51B1CD = 0xC3;
}