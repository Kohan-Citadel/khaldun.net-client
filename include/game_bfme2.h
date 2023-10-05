// game_bfme2.h

#ifndef __GAME_BFME2_H
#define __GAME_BFME2_H

#include "include/global.h"
#include "iathook/iathook.h"

static const char* bfme2_options_ini = 
  "AudioLOD = High\r\n"            \
  "FlashTutorial = 0\r\n"          \
  "HasSeenLogoMovies = yes\r\n"    \
  "IdealStaticGameLOD = High\r\n"  \
  "Resolution = 1024 768\r\n"      \
  "StaticGameLOD = High\r\n"       \
  "TimesInGame = 6\r\n";

LPHOSTENT __stdcall hk_gethostbyname(const char* name);

LPHOSTENT __stdcall bfme2_hk_gethostbyname(const char* name) {
  if (name && !__strcmp(name, "servserv.generals.ea.com"))
    return ogethostbyname("motd.openspy.net");
  else if (name && !__strcmp(name, "bfme2.fesl.ea.com"))
    return ogethostbyname("bfme2.fesl.openspy.net");
  else
    return hk_gethostbyname(name);
}

__forceinline static void bfme2_hook_gs() {
  HOOK_FUNC(0, gethostbyname, bfme2_hk_gethostbyname, "ws2_32.dll", 0, TRUE); // OFT missing
  HOOK_FUNC(0, gethostbyname, bfme2_hk_gethostbyname, "wsock32.dll", 0, TRUE); // OFT missing
}

// missing options.ini causes crash on startup
__forceinline static void bfme2_create_options() {
  char path[MAX_PATH+40];
  HANDLE hFile = 0;
  DWORD dw = 0;
  if (SHGetFolderPath(NULL, CSIDL_APPDATA, NULL, 0, path) >= 0) {
    __strcat(path, "\\My Battle for Middle-earth(tm) II Files");
    CreateDirectoryA(path, NULL);
    __strcat(path, "\\options.ini");
    hFile = CreateFileA(path, GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile && hFile != INVALID_HANDLE_VALUE) {
      WriteFile(hFile, bfme2_options_ini, 150, &dw, NULL);
      CloseHandle(hFile);
    }
  }
}

__noinline static void patch_bfme2() {
  bfme2_hook_gs();
  bfme2_create_options();
}

#endif // __GAME_BFME2_H