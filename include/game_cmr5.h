// game_cmr5.h

#ifndef __GAME_CMR5_H
#define __GAME_CMR5_H

#include "include/global.h"
#include "iathook/iathook.h"

typedef long (__stdcall* RegQueryValueExA_fn)(HKEY hKey, LPCSTR lpValueName, LPDWORD lpReserved, LPDWORD lpType, LPBYTE lpData, LPDWORD lpcbData);
RegQueryValueExA_fn cmr5_oRegQueryValueExA;

// Enable GameSpy
long __stdcall cmr5_hk_RegQueryValueExA(HKEY hKey, LPCSTR lpValueName, LPDWORD lpReserved, LPDWORD lpType, LPBYTE lpData, LPDWORD lpcbData) {
  if (lpValueName && !__strcmp(lpValueName, "CD_KEY")) {
    if (lpType) *lpType = REG_SZ;
    if (lpData) __strcpy(lpData, "LUQJGU030302-MZVGDZYXYXYW");
    if (lpcbData) *lpcbData = 26;
    return 0;
  }
  return cmr5_oRegQueryValueExA(hKey, lpValueName, lpReserved, lpType, lpData, lpcbData);
}

__forceinline static void cmr5_enable_gs() {
    cmr5_oRegQueryValueExA = (RegQueryValueExA_fn)detour_iat_func(0, "RegQueryValueExA", (void*)cmr5_hk_RegQueryValueExA, 0, 0, TRUE);
}

static void patch_cmr5() {
  cmr5_enable_gs();
}

#endif // __GAME_CMR5_H
