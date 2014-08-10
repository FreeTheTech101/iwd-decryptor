// ==========================================================
// IW4M project
// 
// Component: clientdll
// Sub-component: steam_api
// Purpose: Handling of encrypted archive files.
//
// Initial author: NTAuthority
// Started: 2013-06-19
// ==========================================================

#include "StdInc.h"
#include "Hooking.h"

#define LTM_DESC
#include <tomcrypt.h>

#include "IWDKey.h"

static CRITICAL_SECTION iwdCryptCS;

static unsigned int secureKey[256];
static bool secureKeyInited = false;

static void InitSecureKey()
{
	for (int i = 0; i < sizeof(secureKey) / sizeof(int); i++)
	{
		secureKey[i] = *(unsigned int*)(&dynkey[i * 4]);
	}

	secureKeyInited = true;
}

static void FS_DecryptAESKey(unsigned char* key)
{
	register_hash(&sha256_desc);

	rsa_key rkey;
	int hash = find_hash("sha256");
	rsa_import(iwdPKey, sizeof(iwdPKey), &rkey);

	unsigned long outLen = 24;
	int stat;
	rsa_decrypt_key_ex(iwdKey, sizeof(iwdKey), key, &outLen, 0, 0, hash, 2, &stat, &rkey);
	rsa_free(&rkey);
}

symmetric_CTR iwdCTR;

void FS_InitCrypto()
{
	register_cipher(&aes_desc);

	unsigned char key[24];
	FS_DecryptAESKey(key);

	int iv[4];
	iv[0] = 0x1010101;
	iv[1] = 0x1010101;
	iv[2] = 0x1010101;
	iv[3] = 0x1010101;

	int cipher = find_cipher("aes");
	ctr_start(cipher, (unsigned char*)iv, key, sizeof(key), 0, CTR_COUNTER_BIG_ENDIAN, &iwdCTR);
}

static DWORD tlsIWDKey;

// TODO: replace with crc32 as it's nothing 'secure' whatsoever
int FS_GetIWDKey(const char* filename, int length_, int some0)
{
	if (!secureKeyInited)
	{
		InitSecureKey();
	}

	int key = ~some0;

	/*for (int i = 0; i < length; i++)
	{
		key = secureKey[(BYTE)(key ^ filename[i])] ^ ((DWORD)(key >> 8));
	}*/

	__asm
	{
		xor eax, eax
		push esi
		mov esi, filename

		mov ecx, length_

		push edi
		push edx
		mov edx, key

theLoop:
		movzx edi, byte ptr [eax + esi]
		xor edi, edx
		and edi, 0FFh
		shr edx, 8
		xor edx, secureKey[edi * 4]
		inc eax
		cmp eax, ecx
		jl theLoop

		mov key, edx

		pop edx
		pop edi
		pop esi
	}

	return ~key;
}

struct unz_s
{
	FILE* file;
	char pad[124];
	int encrypted;
	int fileKey;
};

static unz_s* unzunz;

int FS_IsFileEncrypted(const char* filename)
{
	return (strstr(filename, "iw_image") || 
			strstr(filename, "iw_model") || 
			strstr(filename, "iw_config") || 
			strstr(filename, "iw_sound") || 
			strstr(filename, "iw_ui_image") ||
			strstr(filename, "iw_adlc"));
}

void FS_LoadZipFile_getFileKey(unz_s* uf, const char* filename)
{
	unzunz = uf;

	uf->encrypted = FS_IsFileEncrypted(filename);
	uf->fileKey = FS_GetIWDKey(filename, strlen(filename), 0);

	TlsSetValue(tlsIWDKey, (LPVOID)uf->fileKey);
}

void __declspec(naked) FS_LoadZipFile_getFileKeyHook()
{
	__asm
	{
		mov eax, [esp + 184h + 8]
		push eax
		mov eax, [esp + 8]
		push eax
		call FS_LoadZipFile_getFileKey
		add esp, 8h

		// unzGoToFirstFile
		push 4D71D0h
		retn
	}
}

void FS_LoadZipFile_setIV(int index)
{
	int iv[4];
	iv[0] = 0x1010101;
	iv[1] = (int)TlsGetValue(tlsIWDKey);
	iv[2] = index;
	iv[3] = 0x1010101;

	ctr_setiv((unsigned char*)iv, sizeof(iv), &iwdCTR);
}

void __declspec(naked) FS_LoadZipFile_setIV1Hook()
{
	__asm
	{
		push edi // file index
		call FS_LoadZipFile_setIV
		add esp, 4h

		// unzGetCurrentFileInfo
		push 444A60h
		retn
	}
}

void __declspec(naked) FS_LoadZipFile_setIV2Hook()
{
	__asm
	{
		mov eax, [esp + 1A0h - 158h]
		push eax // file index
		call FS_LoadZipFile_setIV
		add esp, 4h

		// unzGetCurrentFileInfo
		push 444A60h
		retn
	}
}

struct pakfile_t
{
	char pad[804];
	int fileKey;
};

static std::unordered_map<DWORD, pakfile_t*> _filePtrToPakFile;

void FS_LoadZipFile_storeFileKeyDo(pakfile_t* pakFile)
{
	pakFile->fileKey = (int)TlsGetValue(tlsIWDKey);

	_filePtrToPakFile[(DWORD)unzunz->file] = pakFile;
}

void __declspec(naked) FS_LoadZipFile_storeFileKey()
{
	__asm
	{
		push esi
		call FS_LoadZipFile_storeFileKeyDo
		add esp, 4h

		// _crc32
		push 4B1330h
		retn
	}
}

void unzGetCurrentFileInfo_decrypt(unsigned char* buffer, size_t length, unz_s* unzFile)
{
	if (unzFile->encrypted)
	{
		EnterCriticalSection(&iwdCryptCS);
		ctr_decrypt(buffer, buffer, length, &iwdCTR);
		LeaveCriticalSection(&iwdCryptCS);
	}
}

static void* unzBuffer;

void __declspec(naked) unzGetCurrentFileInfo_decryptHook()
{
	__asm
	{
		mov unzBuffer, eax
		mov eax, 44E830h
		call eax

		add esp, 0Ch
		cmp eax, edi
		jz carryOn

		or ebp, 0FFFFFFFFh

carryOn:
		sub edx, edi
		test ebp, ebp

		jnz returnOtherFalse

		mov eax, unzBuffer
		push esi
		push edi
		push eax
		call unzGetCurrentFileInfo_decrypt
		add esp, 0Ch

		mov edi, [esp + 3Ch]

		push 65C443h
		retn

returnOtherFalse:
		mov edi, [esp + 3Ch]

		push 65C4AAh
		retn
	}
}

void unzReadCurrentFile_decrypt(unsigned char* buffer, int length, int positionInFile, DWORD file, unz_s* zFile)
{
	int iv[4];
	iv[0] = positionInFile;
	iv[1] = zFile->fileKey;//_filePtrToPakFile[file]->fileKey;
	iv[2] = 0x1010101;
	iv[3] = 0x1010101;

	EnterCriticalSection(&iwdCryptCS);
	ctr_setiv((unsigned char*)iv, sizeof(iv), &iwdCTR);
	ctr_decrypt(buffer, buffer, length, &iwdCTR);
	LeaveCriticalSection(&iwdCryptCS);
}

void __declspec(naked) unzReadCurrentFile_decryptHook()
{
	__asm
	{
		test edi, edi
		jz continued

		mov eax, [esp + 14h]
		mov eax, [eax + 80h]
		test eax, eax

		jz continued

		mov eax, [esp + 14h]
		push eax

		mov eax, [esi + 54h]
		push eax

		mov eax, [esi + 38h]
		push eax
		push edi

		mov ecx, [esi]
		push ecx
		call unzReadCurrentFile_decrypt
		add esp, 14h

continued:
		mov edx, [esi]
		add [esi + 38h], edi
		sub [esi + 4Ch], edi
		mov [esi + 4], edx
		mov [esi + 8], edi

		push 4302D3h
		retn
	}
}

void PatchMW2_CryptoZone();
void PatchMW2_CryptoFilesStreamDebug();

void PatchMW2_CryptoFiles()
{
	PatchMW2_CryptoZone();

	tlsIWDKey = TlsAlloc();

	ltc_mp = ltm_desc;

	call(0x486212, FS_InitCrypto, PATCH_JUMP);

	call(0x64248A, FS_LoadZipFile_getFileKeyHook, PATCH_CALL);
	call(0x6424BB, FS_LoadZipFile_setIV1Hook, PATCH_CALL);
	call(0x642660, FS_LoadZipFile_setIV2Hook, PATCH_CALL);

	call(0x642737, FS_LoadZipFile_storeFileKey, PATCH_CALL);

	call(0x65C42A, unzGetCurrentFileInfo_decryptHook, PATCH_JUMP);

	call(0x4302C5, unzReadCurrentFile_decryptHook, PATCH_JUMP);

	// unz_s size
	*(DWORD*)0x431EE6 += 8;
	*(DWORD*)0x4B5348 += 8; // unz_s clone function
	*(DWORD*)0x4B5356 += 8; // needed for multiple files to be loaded simultaneously?

	// packfile_t size
	*(DWORD*)0x642549 += 4;
	*(DWORD*)0x64255A += 4;

	InitializeCriticalSection(&iwdCryptCS);

	//PatchMW2_CryptoFilesStreamDebug();
}