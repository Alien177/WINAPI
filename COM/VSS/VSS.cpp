#include <Windows.h>
#include <stdio.h>
#include <Shlwapi.h>
#include <vss.h>
#include <vswriter.h>
#include <vsbackup.h>

#include <vsadmin.h>
#include <vsmgmt.h>

#include <comdef.h>
#include <objbase.h>

#pragma comment(lib, "VssApi.lib")

void PrintGUID(VSS_ID id) {
    WCHAR guidString[64];
    int chars = StringFromGUID2(id, guidString, ARRAYSIZE(guidString));
    if (chars > 0) {
        wprintf(L"%s\n", guidString);
    }
}

int main()
{
    IVssSnapshotMgmt* pMgmt = nullptr;

    const VSS_ID ProviderId = { 0xb5946137,
                                0x7b9f,
                                0x4925,
                              { 0xaf,0x80,0x51,0xab,0xd6,0xb,0x20,0xd5 } };
    
    IVssEnumMgmtObject* pEnumVolumes = nullptr;

    VSS_MGMT_OBJECT_PROP mgmtProp = {};
    ULONG fetched = 0;

    IVssBackupComponents* pBackup = nullptr;

    HRESULT hr = CoInitializeEx(nullptr, COINITBASE_MULTITHREADED);
    
    if (SUCCEEDED(hr)) { 
        printf("[+] Initialized COM library.\n"); 
    } else { 
        goto quit; 
    }

    hr = CoCreateInstance(CLSID_VssSnapshotMgmt, nullptr, CLSCTX_ALL, IID_IVssSnapshotMgmt, (void**)&pMgmt);
    if (SUCCEEDED(hr)) {
        printf("[+] Obtained an instance of IVssSnapshotMgmt interface.\n");
    }
    else {
        printf("[-] Failed to obtain an instance of IVssSnapshotMgmt interface: 0x%08X\n", hr);
        goto quit;
    }

    hr = pMgmt->QueryVolumesSupportedForSnapshots(ProviderId, VSS_CTX_ALL, &pEnumVolumes);
    if (SUCCEEDED(hr)) {
        printf("[+] IVssSnapshotMgmt::QueryVolumesSupportedForSnapshots succeeded. We have an instance of IVssEnumMgmtObject.\n");
    }
    else {
        printf("[-] IVssSnapshotMgmt::QueryVolumesSupportedForSnapshots failed: 0x%08X\n", hr);
        goto quit;
    }

    hr = CreateVssBackupComponents(&pBackup);
    if (SUCCEEDED(hr)) { 
        printf("[+] Obtained an instance of IVssBackupComponents interface.\n"); 
    }
    else {
        printf("[-] Failed to obtain an instance of IVssBackupComponents interface: 0x%08X\n", hr);
        goto quit;
    }

    hr = pBackup->InitializeForBackup();
    if (SUCCEEDED(hr)) {
        printf("[+] Initialized the backup components metadata in preparation for deletion.\n");
    }
    else {
        printf("[-] Failed to initialize the backup components metadata: 0x%08X\n", hr);
        goto quit;
    }

    hr = pBackup->SetContext(VSS_CTX_ALL);
    if (SUCCEEDED(hr)) {
        printf("[+] Set the context for subsequent shadow copy-related operations.\n");
    }
    else {
        printf("[-] Failed to set the context for subsequent shadow copy-related operations: 0x%08X\n", hr);
        goto quit;
    }

    while (pEnumVolumes->Next(1, &mgmtProp, &fetched) == S_OK && fetched == 1) {

        if (mgmtProp.Type == VSS_MGMT_OBJECT_VOLUME) {

            BSTR volumeName = SysAllocString(mgmtProp.Obj.Vol.m_pwszVolumeName);

            IVssEnumObject* pEnumSnaps = nullptr;
            hr = pMgmt->QuerySnapshotsByVolume(volumeName, ProviderId, &pEnumSnaps);
            if (SUCCEEDED(hr) && pEnumSnaps) {
                VSS_OBJECT_PROP snapProp = {};
                ULONG snapFetched = 0;

                while (pEnumSnaps->Next(1, &snapProp, &snapFetched) == S_OK && snapFetched == 1) {
                    VSS_ID snapID = snapProp.Obj.Snap.m_SnapshotId;
                    LONG deleted = 0;
                    VSS_ID nonDeleteID = GUID_NULL;

                    hr = pBackup->DeleteSnapshots(snapID, VSS_OBJECT_SNAPSHOT, TRUE, &deleted, &nonDeleteID);
                    if (SUCCEEDED(hr)) {
                        printf("[+] Snapshot deleted: ");
                        PrintGUID(snapID);
                    }
                    else {
                        printf("[+] Failed to delete snapshot: ");
                        PrintGUID(snapID);
                    }

                    VssFreeSnapshotProperties(&snapProp.Obj.Snap);
                }
            }
            else {
                printf("[-] Failed to enumerate snapshots by volume for volume: %ws\n", volumeName);
            }
        
            if(mgmtProp.Obj.Vol.m_pwszVolumeName) {
                CoTaskMemFree(mgmtProp.Obj.Vol.m_pwszVolumeName);
            }

            if (pEnumSnaps) { pEnumSnaps->Release(); }
        }
    }

quit: 
    
    if (pMgmt) { pMgmt->Release(); }
    if (pEnumVolumes) { pEnumVolumes->Release(); }
    if (pBackup) { pBackup->Release(); }

    CoUninitialize();
    return 0;
}  
