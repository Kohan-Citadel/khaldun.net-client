// global.h

#ifndef __GLOBAL_H
#define __GLOBAL_H

// Windows XP+
#define WINVER 0x0501
#define _WIN32_WINNT 0x0501

#define _CRT_NONSTDC_NO_WARNINGS
#define _CRT_SECURE_NO_WARNINGS
#define _WINSOCK_DEPRECATED_NO_WARNINGS
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <wininet.h>
#include <iphlpapi.h>
#include <shellapi.h>
#include <shlobj.h>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "iphlpapi.lib")

#if defined(_MSC_VER) && _MSC_VER < 1800
#pragma comment(linker, "/IGNORE:4104")
#endif

#define __noinline __declspec(noinline)

#define HOOK_FUNC(MOD_PTR, FUNC_NAME, FUNC_PTR, MOD_NAME, FUNC_ORD, PIN)                                                 \
  {                                                                                                                      \
    if (o ## FUNC_NAME)                                                                                                  \
      detour_iat_func(MOD_PTR, #FUNC_NAME, (void*)FUNC_PTR, MOD_NAME, FUNC_ORD, PIN);                                    \
    else                                                                                                                 \
      o ## FUNC_NAME = (FUNC_NAME ## _fn)detour_iat_func(MOD_PTR, #FUNC_NAME, (void*)FUNC_PTR, MOD_NAME, FUNC_ORD, PIN); \
  }

#define DLL_PROXY_DELAY_LOAD

// Skip intro
static int skip_intro = 1;

typedef int (__stdcall *bind_fn)(SOCKET s, /* const */ struct sockaddr *addr, int namelen);
bind_fn obind = 0;
typedef LPHOSTENT (__stdcall *gethostbyname_fn)(const char* name);
gethostbyname_fn ogethostbyname = 0;
typedef HANDLE (__stdcall *WSAAsyncGetHostByName_fn)(HWND hWnd, unsigned int wMsg, const char *name, char *buf, int buflen);
WSAAsyncGetHostByName_fn oWSAAsyncGetHostByName = 0;
typedef long (__stdcall* RegOpenKeyExA_fn)(HKEY hKey, LPCSTR lpSubKey, DWORD ulOptions, REGSAM samDesired, PHKEY phkResult);
RegOpenKeyExA_fn oRegOpenKeyExA;
typedef long (__stdcall* RegQueryValueExA_fn)(HKEY hKey, LPCSTR lpValueName, LPDWORD lpReserved, LPDWORD lpType, LPBYTE lpData, LPDWORD lpcbData);
RegQueryValueExA_fn oRegQueryValueExA;
typedef long (__stdcall* RegCloseKey_fn)(HKEY hKey);
RegCloseKey_fn oRegCloseKey;
typedef HMODULE (__stdcall *LoadLibraryA_fn)(LPCSTR lpLibFileName);
LoadLibraryA_fn oLoadLibraryA = 0;

static char gSysDir[MAX_PATH+2];
static unsigned int gSysLen = 0;

static BYTE GSPubKey[] = "BF05D63E93751AD4A59A4A7389CF0BE8A22CCDEEA1E7F12C062D6E194472EFDA5184CCECEB4FBADF5EB1D7ABFE91181453972AA971F624AF9BA8F0F82E2869FB7D44BDE8D56EE50977898F3FEE75869622C4981F07506248BD3D092E8EA05C12B2FA37881176084C8F8B8756C4722CDC57D2AD28ACD3AD85934FB48D6B2D2027";
static BYTE OSPubKey[] = "AFB5818995B3708D0656A5BDD20760AEE76537907625F6D23F40BF17029E56808D36966C0804E1D797E310FEDD8C06E6C4121D963863D765811FC9BAEB2315C9A6EAEB125FAD694D9EA4D4A928F223D9F4514533F18A5432DD0435C5C6AC8E276CF29489CB5AC880F16B0D7832EE927D4E27D622D6A450CD1560D7FA882C6C13";

#pragma function(memset)
void* __cdecl memset(void* dst, int val, size_t count) {
    void* start = dst;
    while (count--) {
        *(char*)dst = (char)val;
        dst = (char*)dst + 1;
    }
    return start;
}

__forceinline static unsigned int __strlen(const char* s) {
  unsigned int i = 0;
  while (s[i] != 0) i++;
  return i;
}
__forceinline static void __strcpy(char* dst, const char* src) {
  while (*src != 0) *dst++ = *src++;
  *dst = 0;
}
__forceinline static char* __strrchr(const char* s, char c) {
  char *p = 0;
  while (*s != 0) {
    if (*s == c)
      p = (char*)s;
    s++;
  }
  return p;
}
__forceinline static char* __strncpy(char* dst, const char* src, unsigned int len) {
  unsigned int i;
  for (i = 0; i < len; i++) {
    if (src[i] == 0) break;
    dst[i] = src[i];
  }
  dst[i] = 0;
  return dst;
}
__forceinline static void __strcat(char* dst, const char* src) {
  while (*dst) dst++;
  __strcpy(dst, src);
}
// s2 should be in lowercase
__forceinline static char* __stristr(const char* s1, const char* s2) {
  unsigned int i;
  char *p;
  for (p = (char*)s1; *p != 0; p++) {
    i = 0;
    do {
      if (s2[i] == 0) return p;
      if (p[i] == 0) break;
      if (s2[i] != ((p[i]>64 && p[i]<91) ? (p[i]+32):p[i])) break;
    } while (++i);
  }
  return 0;
}
__forceinline static char* __strstr(const char* s1, const char* s2) {
  unsigned int i;
  char *p;
  for (p = (char*)s1; *p != 0; p++) {
    i = 0;
    do {
      if (s2[i] == 0) return p;
      if (p[i] == 0) break;
      if (s2[i] != p[i]) break;
    } while (++i);
  }
  return 0;
}
__forceinline static int __strncmp(const char* s1, const char* s2, unsigned int len) {
  while (*s1 == *s2) {
    if (*s1 == 0 || --len == 0) return 0;
    s1++; s2++;
  }
  return (*s1 > *s2) ? 1 : -1;
}
__forceinline char* __htoa(unsigned short h, char* a) {
  if (h < 10) {
    a[0] = '0' + h;
    a[1] = 0;
  } else if (h < 100) {
    a[0] = '0' + (h / 10);
    a[1] = '0' + (h % 10);
    a[2] = 0;
  } else if (h < 1000) {
    a[0] = '0' + (h / 100);
    a[1] = '0' + (h % 100) / 10;
    a[2] = '0' + (h % 10);
    a[3] = 0;
  } else if (h < 10000) {
    a[0] = '0' + (h / 1000);
    a[1] = '0' + (h % 1000) / 100;
    a[2] = '0' + (h % 100) / 10;
    a[3] = '0' + (h % 10);
    a[4] = 0;
  } else {
    a[0] = '0' + (h / 10000);
    a[1] = '0' + (h % 10000) / 1000;
    a[2] = '0' + (h % 1000) / 100;
    a[3] = '0' + (h % 100) / 10;
    a[4] = '0' + (h % 10);
    a[5] = 0;
  }
  return a;
}
__forceinline static int __memcmp(const void* p1, const void* p2, unsigned int len) {
  while (*(char*)p1 == *(char*)p2) {
    if (--len == 0) return 0;
    p1 = (char*)p1 + 1;
    p2 = (char*)p2 + 1;
  }
  return (*(char*)p1 > *(char*)p2) ? 1 : -1;
}
__forceinline static char* h2hex(short h, char* s) {
  s[0] = ((h>>12)&0xF)<10?((h>>12)&0xF)+48:((h>>12)&0xF)+87;
  s[1] = ((h>>8)&0xF)<10?((h>>8)&0xF)+48:((h>>8)&0xF)+87;
  s[2] = ((h>>4)&0xF)<10?((h>>4)&0xF)+48:((h>>4)&0xF)+87;
  s[3] = (h&0xF)<10?(h&0xF)+48:(h&0xF)+87;
  s[4] = 0;
  return s;
}

__forceinline static BYTE* find_pattern(BYTE* src_start, BYTE* src_end, BYTE* pattern_start, BYTE* pattern_end) {
  BYTE *pos,*end,*s1,*p1;
  end = src_end-(pattern_end-pattern_start);
  for (pos = src_start; pos <= end; pos++) {
    s1 = pos-1;
    p1 = pattern_start-1;
    while (*++s1 == *++p1) {
      if (p1 == pattern_end)
        return pos;
    }
  }
  return src_end;
}

#define _ANY 0x100
__forceinline static BYTE* find_pattern_wildcard(BYTE* src_start, BYTE* src_end, WORD* pattern_start, WORD* pattern_end) {
  BYTE *pos,*end,*s1;
  WORD *p1;
  end = src_end-((pattern_end-pattern_start) >> 1);
  for (pos = src_start; pos <= end; pos++) {
    s1 = pos-1;
    p1 = pattern_start-1;
    while (*++s1 == (BYTE)*++p1 || *p1 == _ANY) {
      if (p1 == pattern_end)
        return pos;
    }
  }
  return src_end;
}

__forceinline static BYTE* find_pattern_mem(ULONG_PTR addr, BYTE* search, BYTE* search_end, BOOL executable) {
  MEMORY_BASIC_INFORMATION memBI;
  BYTE* res;

  if (!addr)
    addr = (ULONG_PTR)GetModuleHandleA(0); // start search at proc base addr
  memset(&memBI, 0, sizeof(memBI));
  while (VirtualQuery((void*)addr, &memBI, sizeof(memBI))) {
    // skip noncommitted and guard pages, nonreadable or nonexecutable pages
    if ((memBI.State & MEM_COMMIT) && (memBI.Protect == ((memBI.Protect & ~(PAGE_NOACCESS | PAGE_GUARD)) & (memBI.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY | (executable ? 0 : (PAGE_READONLY | PAGE_READWRITE | PAGE_WRITECOPY))))))) {
      res = find_pattern((BYTE*)memBI.BaseAddress, (BYTE*)memBI.BaseAddress + memBI.RegionSize, search, search_end);
      if (res != (BYTE*)memBI.BaseAddress + memBI.RegionSize && res != search)
        return res; // found
    }
    addr = (ULONG_PTR)((ULONG_PTR)memBI.BaseAddress+(ULONG_PTR)memBI.RegionSize);
  }
  return 0;
}

__forceinline static BYTE* find_pattern_mem_wildcard(ULONG_PTR addr, WORD* search, WORD* search_end, BOOL executable) {
  MEMORY_BASIC_INFORMATION memBI;
  BYTE* res;

  if (!addr)
    addr = (ULONG_PTR)GetModuleHandleA(0); // start search at proc base addr
  memset(&memBI, 0, sizeof(memBI));
  while (VirtualQuery((void*)addr, &memBI, sizeof(memBI))) {
    // skip noncommitted and guard pages, nonreadable or nonexecutable pages
    if ((memBI.State & MEM_COMMIT) && (memBI.Protect == ((memBI.Protect & ~(PAGE_NOACCESS | PAGE_GUARD)) & (memBI.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY | (executable ? 0 : (PAGE_READONLY | PAGE_READWRITE | PAGE_WRITECOPY))))))) {
      res = find_pattern_wildcard((BYTE*)memBI.BaseAddress, (BYTE*)memBI.BaseAddress + memBI.RegionSize, search, search_end);
      if (res != (BYTE*)memBI.BaseAddress + memBI.RegionSize && res != (BYTE*)search)
        return res; // found
    }
    addr = (ULONG_PTR)((ULONG_PTR)memBI.BaseAddress+(ULONG_PTR)memBI.RegionSize);
  }
  return 0;
}

__forceinline static void write_mem(BYTE* ptr, BYTE* w, unsigned int len) {
  unsigned int i;
  DWORD old_rights = 0;
  DWORD new_rights = 0;
  MEMORY_BASIC_INFORMATION memBI;

  memset(&memBI, 0, sizeof(memBI));
  if (!VirtualQuery((void*)ptr, &memBI, sizeof(memBI)))
    return;

  old_rights = memBI.Protect;
  new_rights = (old_rights & ~(PAGE_NOACCESS | PAGE_GUARD | PAGE_EXECUTE_WRITECOPY | PAGE_WRITECOPY | PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_READONLY)) | (old_rights & (PAGE_EXECUTE_READWRITE | PAGE_READWRITE));

  if (old_rights != new_rights) {
    if ((new_rights & (PAGE_EXECUTE_READWRITE | PAGE_READWRITE)) == 0)
      new_rights |= (old_rights & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_WRITECOPY)) ? PAGE_EXECUTE_READWRITE : PAGE_READWRITE;
    if (!VirtualProtect((void*)ptr, len, new_rights, &old_rights))
      return;
  }

  if (w) {
    for (i = 0; i < len; i++) {
      ptr[i] = w[i];
    }
  } else {
    for (i = 0; i < len; i++) {
      ptr[i] = 0x90;
    }
  }

  if (old_rights != new_rights) {
    VirtualProtect((void*)ptr, len, new_rights, &old_rights);
  }
}

__forceinline static void nop_mem(BYTE* ptr, unsigned int len) {
  write_mem(ptr,0,len);
}

__forceinline static int patch_if_match(BYTE* ptr, BYTE* r, BYTE* w, unsigned int r_len, unsigned int w_len) {
  if(!__memcmp(ptr, r, r_len)) {
    write_mem(ptr, w, w_len);
    return 1;
  }
  return 0;
}

__forceinline static void gs_replace_pubkey(ULONG_PTR addr) {
  BYTE* ptr = 0;

  ptr = find_pattern_mem(addr, GSPubKey, GSPubKey + 255, FALSE);
  if (ptr)
    write_mem(ptr, OSPubKey, 256);
}

__forceinline static int gs_copy_string(char* dst, const char* src, const char* patch_domain) {
  char* p = 0;
  const char* s = src;
  const char* pd = patch_domain;
  while (p = __stristr(s, "gamespy.")) {
    if (((p[8] == 'c' || p[8] == 'C') &&
         (p[9] == 'o' || p[9] == 'O') &&
         (p[10] == 'm' || p[10] == 'M')) ||
        ((p[8] == 'n' || p[8] == 'N') &&
         (p[9] == 'e' || p[9] == 'E') &&
         (p[10] == 't' || p[10] == 'T')))
      break;
    s = p+8;
  }
  if (p) {
    __strncpy(dst, src, 511);
    s = dst+(p-src);
    while (p = __stristr(s, "gamespy.")) {
      if ((p[8] == 'c' || p[8] == 'C') &&
          (p[9] == 'o' || p[9] == 'O') &&
          (p[10] == 'm' || p[10] == 'M')) {
        p[8] = 'n';
        p[9] = 'e';
        p[10] = 't';
      } else if ((p[8] != 'n' && p[8] != 'N') ||
                 (p[9] != 'e' && p[9] != 'E') ||
                 (p[10] != 't' && p[10] != 'T')) {
        s = p+8;
        continue;
      }
      // copies patch_domain into p
      p[0] = pd[0];
      p[1] = pd[1];
      p[2] = pd[2];
      p[3] = pd[3];
      p[4] = pd[4];
      p[5] = pd[5];
      p[6] = pd[6];
      s = p+11;
    }
    return 1;
  }
  return 0;
}

__forceinline static int fesl_copy_string(char* dst, const char* src, const char* patch_domain) {
  char* p = __stristr(src, "fesl.ea.com");
  if (p) {
    p += 5;
    unsigned int len = (((p-src) > 500) ? 500 : (p-src));
    __strncpy(dst, src, len);
    __strcpy(dst+len, patch_domain);
    return 1;
  }
  return 0;
}

__forceinline static BOOL IsWow64(void) {
  void* fnIsWow64Process;
  BOOL bIsWow64 = FALSE;
  HMODULE k32 = GetModuleHandleA("kernel32.dll");
  if (!k32) return FALSE;
  fnIsWow64Process = GetProcAddress(k32, "IsWow64Process");
  return (fnIsWow64Process && ((BOOL (__stdcall *)(HANDLE,PBOOL)) (void*)(fnIsWow64Process))((HANDLE)-1, &bIsWow64) && bIsWow64);
}
__forceinline static UINT GetSysWow64Dir(LPSTR lpBuffer, UINT uSize) {
  void* fnGetSystemWow64DirectoryA;
  HMODULE k32 = GetModuleHandleA("kernel32.dll");
  if (!k32) return 0;
  fnGetSystemWow64DirectoryA = GetProcAddress(k32, "GetSystemWow64DirectoryA");
  if (!fnGetSystemWow64DirectoryA) return 0;
  return ((UINT (__stdcall *)(LPSTR,UINT)) (void*)(fnGetSystemWow64DirectoryA))(lpBuffer, uSize);
}

__forceinline static void InitSysDir() {
  if (IsWow64())
    gSysLen = GetSysWow64Dir(gSysDir, MAX_PATH+1);
  else
    gSysLen = GetSystemDirectoryA(gSysDir, MAX_PATH+1);
    
  if (gSysLen && gSysLen < MAX_PATH) {
    while (gSysDir[gSysLen] == '\0')
      gSysLen--;
    if (gSysDir[gSysLen++] != '\\')
      gSysDir[gSysLen++] = '\\';

    gSysDir[gSysLen] = 0;
  } else {
    gSysLen = 0;
    gSysDir[0] = 0;
  }
}

__forceinline static HMODULE LoadSysMod(const char* modname) {
  char modpath[MAX_PATH+20];
  if (gSysLen) {
    __strcpy(modpath, gSysDir);
    __strcpy(modpath+gSysLen, modname);
    return LoadLibraryA(modpath);
  }

  return 0;
}

static void* GetSysProc(const char* modname, const char* funcname) {
  HMODULE hm;
  hm = LoadSysMod(modname);
  return (hm ? GetProcAddress(hm, funcname) : 0);
}

__forceinline static int FileExistsA(const char* path) {
  if (GetFileAttributesA(path) == INVALID_FILE_ATTRIBUTES) { // 0xFFFFFFFF (-1)
    switch (GetLastError())
    {
      case ERROR_FILE_NOT_FOUND:
      case ERROR_PATH_NOT_FOUND:
      case ERROR_INVALID_NAME:
      case ERROR_INVALID_DRIVE:
      case ERROR_NOT_READY:
      case ERROR_INVALID_PARAMETER:
      case ERROR_BAD_PATHNAME:
      case ERROR_BAD_NETPATH:
        return 0;
      default:
        break;
    }
  }
  return 1;
}

static int LocalDirFileExists(const char* filename) {
  char *p, path[512];
  if (GetModuleFileNameA(GetModuleHandle(0), path, 511)) {
    path[511] = 0;
    p = __strrchr(path, '\\');
    if (p && p-path < 485) {
      __strcpy(++p, filename);
      return FileExistsA(path);
    }
  }
  return 0;
}

static BOOL CreateRegKey(HKEY hKeyRoot, char* subKey) {
  HKEY hKey;
  char *p = subKey;
  while (*++p) {
    if (*p == '\\') {
      *p = 0;
      if (!RegCreateKeyExA(hKeyRoot, subKey, 0, NULL, 0, KEY_WRITE, NULL, &hKey, NULL)) RegCloseKey(hKey);
      *p = '\\';
    }
  }
  if (RegCreateKeyExA(hKeyRoot, subKey, 0, NULL, 0, KEY_WRITE, NULL, &hKey, NULL)) return FALSE;
  RegCloseKey(hKey);
  return TRUE;
}

static char* GetModExpName(HMODULE hModule) {
  PIMAGE_DOS_HEADER img_dos_headers;
  PIMAGE_NT_HEADERS img_nt_headers;
  PIMAGE_DATA_DIRECTORY img_dir_exports;
  PIMAGE_EXPORT_DIRECTORY img_exp_dir;

  if (!hModule)
    return 0;
  img_dos_headers = (PIMAGE_DOS_HEADER)hModule;
  if (img_dos_headers->e_magic != IMAGE_DOS_SIGNATURE)
    return 0;
  img_nt_headers = (PIMAGE_NT_HEADERS)((size_t)img_dos_headers + img_dos_headers->e_lfanew);
  if (img_nt_headers->Signature != IMAGE_NT_SIGNATURE)
    return 0;
  if (img_nt_headers->FileHeader.SizeOfOptionalHeader < 4) // OptionalHeader.Magic
    return 0;
  if (img_nt_headers->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR_MAGIC || img_nt_headers->OptionalHeader.NumberOfRvaAndSizes < 1)
    return 0;

  img_dir_exports = (PIMAGE_DATA_DIRECTORY)(&(img_nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]));
  if (!img_dir_exports->VirtualAddress || img_dir_exports->Size < sizeof(IMAGE_EXPORT_DIRECTORY))
    return 0;

  img_exp_dir = (PIMAGE_EXPORT_DIRECTORY)((size_t)img_dos_headers + img_dir_exports->VirtualAddress);
  return (img_exp_dir->Name ? (char*)((size_t)img_dos_headers + img_exp_dir->Name) : 0);
}

typedef struct _RSDS_DEBUG_FORMAT {
  DWORD Signature;
  GUID Guid;
  DWORD Age;
  CHAR Path[ANYSIZE_ARRAY];
} RSDS_DEBUG_FORMAT, *PRSDS_DEBUG_FORMAT;

static LPGUID GetModPdbGuid(HMODULE hModule) {
  PIMAGE_DOS_HEADER img_dos_headers;
  PIMAGE_NT_HEADERS img_nt_headers;
  PIMAGE_DATA_DIRECTORY img_dir_debug;
  PIMAGE_DEBUG_DIRECTORY img_dbg_dir;
  PRSDS_DEBUG_FORMAT img_codeview;

  if (!hModule)
    return 0;
  img_dos_headers = (PIMAGE_DOS_HEADER)hModule;
  if (img_dos_headers->e_magic != IMAGE_DOS_SIGNATURE)
    return 0;
  img_nt_headers = (PIMAGE_NT_HEADERS)((size_t)img_dos_headers + img_dos_headers->e_lfanew);
  if (img_nt_headers->Signature != IMAGE_NT_SIGNATURE)
    return 0;
  if (img_nt_headers->FileHeader.SizeOfOptionalHeader < 4) // OptionalHeader.Magic
    return 0;
  if (img_nt_headers->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR_MAGIC || img_nt_headers->OptionalHeader.NumberOfRvaAndSizes < 7)
    return 0;

  img_dir_debug = (PIMAGE_DATA_DIRECTORY)(&(img_nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG]));
  if (!img_dir_debug->VirtualAddress || img_dir_debug->Size < sizeof(IMAGE_DEBUG_DIRECTORY))
    return 0;

  img_dbg_dir = (PIMAGE_DEBUG_DIRECTORY)((size_t)img_dos_headers + img_dir_debug->VirtualAddress);
  if (img_dbg_dir->Type != IMAGE_DEBUG_TYPE_CODEVIEW || !img_dbg_dir->PointerToRawData) // img_dbg_dir->AddressOfRawData ?
    return 0;

  img_codeview = (PRSDS_DEBUG_FORMAT)((size_t)img_dos_headers + img_dbg_dir->PointerToRawData);

  return ((img_codeview->Signature == 0x53445352) ? &(img_codeview->Guid) : 0);
}

#endif // __GLOBAL_H
