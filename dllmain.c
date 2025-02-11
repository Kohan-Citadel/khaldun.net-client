// dllmain.c

/*
 * Khaldun.net Client
 * https://github.com/Kohan-Citadel/khaldun.net-client
 *
 */
#include "include/global.h"
#include "include/shared.h"
#include "include/dinput_dll.h"

#include "include/picoupnp.h"
#include "iathook/iathook.h"

#include <stdio.h>
#include <winsock2.h>

#pragma comment(lib, "Shell32.lib")    // ShellExecute library
#pragma comment(lib, "advapi32.lib")   // RegEdit Library
#pragma comment(lib, "ws2_32.lib")     // Winsock Library
//#pragma comment(lib, "msvcrt.lib")

char* patch_domain;

// Redirect all bind() to 0.0.0.0
static int force_bind_ip = 1;

static int enable_upnp = 1;

typedef HINTERNET (__stdcall *InternetOpenUrlA_fn)(HINTERNET hInternet, LPCSTR lpszUrl, LPCSTR lpszHeaders, DWORD dwHeadersLength, DWORD dwFlags, DWORD_PTR dwContext);
InternetOpenUrlA_fn oInternetOpenUrlA = 0;

unsigned long __stdcall portMapThread(void* param) {
  AddPortMapping((unsigned short)param, (unsigned long)param >> 16);
  return 0;
}

int __stdcall hk_bind(SOCKET s, struct sockaddr *addr, int namelen) {
  int ret, type;
  int len = sizeof(int);

  if (addr->sa_family != AF_INET)
    return obind(s, addr, namelen);

  // Bind to 0.0.0.0 (any)
  if (force_bind_ip && (*(unsigned long*)(&addr->sa_data[2]) != 0))
    *(unsigned long*)(&addr->sa_data[2]) = 0;

  getsockopt(s, SOL_SOCKET, SO_TYPE, (char*)&type, &len);
  ret = obind(s, addr, namelen);

  if (enable_upnp && (type == SOCK_STREAM || type == SOCK_DGRAM)) {
    unsigned long param = (unsigned long)ntohs(*(unsigned short*)(addr->sa_data));
    if (param == 0) {
      struct sockaddr_in sin;
      int addrlen = sizeof(struct sockaddr_in);
      if(getsockname(s, (struct sockaddr *)&sin, &addrlen) || sin.sin_family != AF_INET || addrlen != sizeof(struct sockaddr_in))
        return ret;
      param = (unsigned long)ntohs(sin.sin_port);
    }
    param |= ((type == SOCK_STREAM ? IPPROTO_TCP : IPPROTO_UDP) << 16);
    CloseHandle(CreateThread(0, 0, portMapThread, (void*)param, 0, 0));
  }

  return ret;
}

LPHOSTENT __stdcall hk_gethostbyname(const char* name) {
  char s[512];
  if (name && gs_copy_string(s, name, patch_domain))
    return ogethostbyname(s);
  else if (name && fesl_copy_string(s, name))
    return ogethostbyname(s);
  else
    return ogethostbyname(name);
}

HANDLE __stdcall hk_WSAAsyncGetHostByName(HWND hWnd, unsigned int wMsg, const char *name, char *buf, int buflen) {
  char s[512];
  if (name && gs_copy_string(s, name, patch_domain))
    return oWSAAsyncGetHostByName(hWnd, wMsg, s, buf, buflen);
  else
    return oWSAAsyncGetHostByName(hWnd, wMsg, name, buf, buflen);
}

HINTERNET __stdcall hk_InternetOpenUrlA(HINTERNET hInternet, LPCSTR lpszUrl, LPCSTR lpszHeaders, DWORD dwHeadersLength, DWORD dwFlags, DWORD_PTR dwContext) {
  char s[512];
  if (lpszUrl && gs_copy_string(s, lpszUrl, patch_domain))
    return oInternetOpenUrlA(hInternet, s, lpszHeaders, dwHeadersLength, dwFlags, dwContext);
  else
    return oInternetOpenUrlA(hInternet, lpszUrl, lpszHeaders, dwHeadersLength, dwFlags, dwContext);
}

static char* securom_msg = "mshta.exe vbscript:Execute(\"msgbox \"\"Your game executable is infested with SecuROM.\"\" & chr(10) & \"\"Process was exit to prevent damage to your operating system.\"\",0,\"\"Notice\"\":close\")";
__forceinline static int securom_check(HMODULE hModule) {
    PIMAGE_DOS_HEADER img_dos_headers;
    PIMAGE_NT_HEADERS img_nt_headers;
    PIMAGE_SECTION_HEADER img_sec_header;
    unsigned int n;

    img_dos_headers = (PIMAGE_DOS_HEADER)GetModuleHandleA(0);
    if (img_dos_headers->e_magic != IMAGE_DOS_SIGNATURE)
      return 0;
    img_nt_headers = (PIMAGE_NT_HEADERS)((size_t)img_dos_headers + img_dos_headers->e_lfanew);
    if (img_nt_headers->Signature != IMAGE_NT_SIGNATURE)
      return 0;
    if (img_nt_headers->FileHeader.SizeOfOptionalHeader < 4) // OptionalHeader.Magic
      return 0;
    if (img_nt_headers->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR_MAGIC)
      return 0;

    img_sec_header = (PIMAGE_SECTION_HEADER)((size_t)img_nt_headers + sizeof(img_nt_headers->Signature) + sizeof(img_nt_headers->FileHeader) + img_nt_headers->FileHeader.SizeOfOptionalHeader);
    for (n = 0; n < img_nt_headers->FileHeader.NumberOfSections; n++, img_sec_header++) {
      if (img_sec_header->Name && !__strncmp(img_sec_header->Name, ".securom", 8)) {
        STARTUPINFO si;
        PROCESS_INFORMATION pi;
        memset(&si, 0, sizeof(STARTUPINFO));
        memset(&pi, 0, sizeof(PROCESS_INFORMATION));
        if(CreateProcessA(0, securom_msg, 0, 0, 0, 0, 0, 0, &si, &pi)) {
          CloseHandle(pi.hThread);
          CloseHandle(pi.hProcess);
        }
        ExitProcess(1);
        return 1;
      }
    }
    return 0;
}

unsigned long __stdcall teredoThread(void* param) {
  HKEY hKey;
  char data[16];
  DWORD type = 0;
  DWORD cb = sizeof(data);

  if (!RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SOFTWARE\\Policies\\Microsoft\\Windows\\TCPIP\\v6Transition", 0, KEY_QUERY_VALUE, &hKey)) {
    if (RegQueryValueExA(hKey, "Teredo_State", NULL, &type, data, &cb)) type = 0;
    RegCloseKey(hKey);
  }

  if (type != REG_SZ || *(unsigned long long*)data != 0x64656C6261736944ULL)
    ShellExecuteA(NULL, "runas", "cmd.exe", "/d/x/s/v:off/r \"reg add HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\TCPIP\\v6Transition /f /v Teredo_State /t REG_SZ /d Disabled & netsh interface teredo set state disabled\"", NULL, SW_HIDE);

  return 0;
}

__forceinline static void DisableTeredoTunneling(void) {
  CloseHandle(CreateThread(0, 0, teredoThread, 0, 0, 0));
}

// check if the server is up, and don't patch if it is
// this prevents the game from hanging if the server is down
// and will allow players to still direct connect
// Return Values:
//  TRUE: sucessfully connected to server and completed handshake with OpenSpy
//    -1: could not connect to server
//    -2: connected to server but didn't receive OpenSpy handshake
// -2 is the issue we care about, because the game will hang indefinitely in this scenario
int serverCheck(const char *hostname) {
  FILE* log = fopen("dinput.log", "a");
  fprintf(log, "Starting Server Check for %s\n", hostname);
  char masterServer[20];
  __strcpy(masterServer, "master.");
  __strcat(masterServer, hostname);

  WSADATA wsa;
	struct hostent *he;
	struct in_addr **addr_list;
	int i;

  SOCKET s;
  struct sockaddr_in server;
  char server_reply[101];
  int recv_size;
	
	fprintf(log, "\nInitialising Winsock...");
	if (WSAStartup(MAKEWORD(2,2),&wsa) != 0)
	{
		fprintf(log, "Failed. Error Code : %d\n\n",WSAGetLastError());
    fclose(log);
    WSACleanup();
		return -1;
	}
	fprintf(log, "Initialised.\n");

  if ( (s = socket( AF_INET , SOCK_STREAM , 0 )) == INVALID_SOCKET)
	{
		fprintf(log, "Could not create socket : %d\n\n" , WSAGetLastError());
    fclose(log);
    WSACleanup();
		return -1;
	}
	fputs("Socket created.\n", log);

  if ( (he = gethostbyname( masterServer ) ) == NULL)
  {
    //gethostbyname failed
    fprintf(log, "gethostbyname failed : %d\n\n" , WSAGetLastError());
    closesocket(s);
    fclose(log);
    WSACleanup();
    return -1;
  }
        
  //Cast the h_addr_list to in_addr , since h_addr_list also has the ip address in long format only
  addr_list = (struct in_addr **) he->h_addr_list;
  
  server.sin_family = AF_INET;
  //if ( __strncmp(hostname, "khaldun.net", 11) == 0 )
  //	server.sin_port = htons( 80 );
  //else
    server.sin_port = htons( 28900 );

  BOOL connected = FALSE;
  for(i = 0; addr_list[i] != NULL; i++) 
  {
    server.sin_addr.s_addr = addr_list[0]->S_un.S_addr;
    fprintf(log, "%s resolved to : %s\n" , masterServer , inet_ntoa( server.sin_addr ));
    //Connect to remote server
    fprintf(log, "Attempting connection to %s...", inet_ntoa(server.sin_addr ));
    if (connect(s , (struct sockaddr *)&server , sizeof(server)) < 0) {
      fputs("connect error\n", log);
    } else {
      fputs("Connected\n", log);
      connected = TRUE;
      break;
    }
  }
  if (!connected) {
    fputs("connection failed for all addresses!\n", log);
    fclose(log);
    closesocket(s);
    WSACleanup();
    return -2;
  }

 
  fprintf(log, "Setting socket timeout...");
  int recvTimeout = 5000;
  int optLen = sizeof(int);
  if (setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (char *) &recvTimeout, optLen) == SOCKET_ERROR) {
    fprintf(log, "setsockopt for SO_RCVTIMEO failed with error: %u\n", WSAGetLastError());
    fclose(log);
    closesocket(s);
    WSACleanup();
    return -2;
  }
  fputs("socket timeout set!\n", log);

  //Receive a reply from the server
  fprintf(log, "Listening for data on %i for %ims...", ntohs(server.sin_port), recvTimeout);
	if((recv_size = recv(s , server_reply , 100 , 0)) == SOCKET_ERROR)
	{
		fputs("recv failed\n", log);
    fclose(log);
    closesocket(s);
    WSACleanup();
    return -2;
	} else {
    fprintf(log, "Reply received. recv_size: %i\n", recv_size);
    fprintf(log, "Extracted string: %s compared with %s\n", server_reply, "\\basic\\\\secure\\");
    
    if (strncmp(server_reply, "\\basic\\\\secure\\", 15) == 0) {
      fputs("Server is online!\n\n", log);
    } else {
      fputs("Server is offline :(\n\n", log);
      fclose(log);
      closesocket(s);
      WSACleanup();
      return -2;
    }
  }
  fflush(log);
  fclose(log);
  closesocket(s);
  WSACleanup();
  return TRUE;
}

static volatile int initialized = 0;
int __stdcall DllMain(HINSTANCE hInstDLL, DWORD dwReason, LPVOID lpReserved) {
  if (dwReason == DLL_PROCESS_ATTACH && !initialized) {
    fclose(fopen("dinput.log", "w"));
    // if khaldun.net is down, fall back on openspy.net
    if (serverCheck("khaldun.net") == TRUE) {
      // server online, so patch for khaldun.net
      patch_domain = "khaldun.net";
    } else if (serverCheck("openspy.net") == TRUE) {
      // fall back on OS and patch for openspy.net
      patch_domain = "openspy.net";
    } else {
      // both servers are down, so don't patch
      patch_domain = "gamespy.net";
    }

    HMODULE hm = 0;
    char* p = 0;

    initialized = 1;
    DisableThreadLibraryCalls(hInstDLL);

    // Pin this module to memory
    GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_PIN, sDInput, &hm);

    // SecuROM guard
    if (!LocalDirFileExists("disable_securom_guard.txt") && securom_check(hm))
      return 1;

    // UPNP
    if (LocalDirFileExists("disable_upnp.txt"))
      enable_upnp = 0;

    // Load system directory to memory
    InitSysDir();

    // Proxy DLL feature
    dinput_hook();

    // Hook API calls
    if (!ogethostbyname) {
      HOOK_FUNC(0, gethostbyname, hk_gethostbyname, "ws2_32.dll", 52, TRUE);
      HOOK_FUNC(0, gethostbyname, hk_gethostbyname, "wsock32.dll", 52, TRUE);
    }
    if (!oWSAAsyncGetHostByName) {
      HOOK_FUNC(0, WSAAsyncGetHostByName, hk_WSAAsyncGetHostByName, "ws2_32.dll", 103, TRUE);
      HOOK_FUNC(0, WSAAsyncGetHostByName, hk_WSAAsyncGetHostByName, "wsock32.dll", 103, TRUE);
    }
    if (!obind) {
      HOOK_FUNC(0, bind, hk_bind, "ws2_32.dll", 2, TRUE);
      HOOK_FUNC(0, bind, hk_bind, "wsock32.dll", 2, TRUE);
    }
    if (!oInternetOpenUrlA)
      HOOK_FUNC(0, InternetOpenUrlA, hk_InternetOpenUrlA, "wininet.dll", 0, TRUE);

    DisableTeredoTunneling();
  }

  return TRUE;
}
