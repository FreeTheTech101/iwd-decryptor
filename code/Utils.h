// ==========================================================
// IW4M project
// 
// Component: clientdll
// Sub-component: steam_api
// Purpose: Various generic utility functions.
//
// Initial author: NTAuthority
// Started: 2010-09-10
// ==========================================================

//#define Trace(source, message, ...) Trace2("[" source "] " message, __VA_ARGS__)
#define Trace2(message, ...) Com_Printf(0, message "\n", __VA_ARGS__)

bool FileExists(const char* file);
size_t FileSize(const char* file);
char * FileDir(const char * path);

#define MERGED_DIR "dump"

// flag settings
#define GAME_FLAG_MERGE		(1 << 0)

#define GAME_FLAG(x)			((_gameFlags & x) == x)

extern unsigned int _gameFlags;
void DetermineGameFlags();

const char* va(const char* format, ...);
const char *getOutFile(const char *name);
void CreateDirectoryAnyDepth(const char *path);
std::vector<std::string> explode(const std::string& str, const std::string& delimiters);