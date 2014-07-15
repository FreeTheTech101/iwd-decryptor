#pragma once

#include "StdInc.h"

#define MAX_ASSET_COUNT 2048
#define MAX_SCRIPT_STRINGS 2048

#define ZONE_STREAM_VERTEX 8
#define ZONE_STREAM_FACE 9

#if _DEBUG
#define Com_Debug Com_Debug_
#else
#define Com_Debug
#endif

typedef struct
{
	int name;
	int type;	
	void* data;
	int offset;
	bool written;
} asset_t;

typedef struct
{
	char* name;
	int scriptStringCount;
	std::string * scriptStrings;
	int assetCount;
	asset_t * assets;
} zoneInfo_t;

// sscanline ish
#define sscanlinef_init(ptr) int __sscanlinef_offset = 0; char* __sscanlinef_at = ptr;
#define _sscanlinef_inc() __sscanlinef_at += __sscanlinef_offset;

#define _sscanlinef(format, ...) sscanf(__sscanlinef_at, format "%n", __VA_ARGS__, &__sscanlinef_offset)
#define sscanlinef(format, ...) _sscanlinef(format, __VA_ARGS__); _sscanlinef_inc();

// Main
extern void loadAsset(zoneInfo_t* info, int type, const char* filename, const char* name);

// Util
extern void Com_Printf(const char* format, ...);
void Com_Error(bool exit, const char* format, ...);
void Com_Debug_(const char* format, ...);
int getAssetTypeForString(const char* str);
const char* getAssetStringForType(int type);
int getArgc();
LPSTR* getArgs();
long flength(FILE* fp);