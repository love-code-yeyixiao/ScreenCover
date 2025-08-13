#include <windows.h>
#include <wincrypt.h>
#include <tchar.h>
#include <iostream>
#pragma comment(lib, "crypt32.lib")

bool AddCertToTrustedRoot(LPCWSTR certFilePath)
{
    bool success = false;
    HANDLE hFile = CreateFileW(certFilePath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        std::wcerr << L"Cannot open certificate file.\n";
        return false;
    }

    DWORD fileSize = GetFileSize(hFile, NULL);
    BYTE* certData = new BYTE[fileSize];
    DWORD bytesRead = 0;

    if (!ReadFile(hFile, certData, fileSize, &bytesRead, NULL)) {
        std::wcerr << L"Failed to read certificate file.\n";
        CloseHandle(hFile);
        delete[] certData;
        return false;
    }
    CloseHandle(hFile);

    // 1. 解析证书
    PCCERT_CONTEXT pCertCtx = CertCreateCertificateContext(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, certData, fileSize);
    delete[] certData;

    if (!pCertCtx) {
        std::wcerr << L"CertCreateCertificateContext failed.\n";
        return false;
    }

    // 2. 打开“受信任的根证书颁发机构”存储区（本地计算机）
    HCERTSTORE hStore = CertOpenStore(
        CERT_STORE_PROV_SYSTEM,
        0,
        NULL,
        CERT_SYSTEM_STORE_LOCAL_MACHINE | CERT_STORE_OPEN_EXISTING_FLAG,
        L"ROOT"
    );

    if (!hStore) {
        std::wcerr << L"CertOpenStore failed. Are you running as administrator?\n";
        CertFreeCertificateContext(pCertCtx);
        return false;
    }

    // 3. 添加证书
    if (!CertAddCertificateContextToStore(hStore, pCertCtx, CERT_STORE_ADD_REPLACE_EXISTING, NULL)) {
        std::wcerr << L"Failed to add certificate to store.\n";
    }
    else {
        std::wcout << L"Certificate added successfully to Trusted Root store.\n";
        success = true;
    }

    // 4. 清理
    CertCloseStore(hStore, 0);
    CertFreeCertificateContext(pCertCtx);
    return success;
}
int wmain(int argc, wchar_t* argv[])
{
    if (argc == 1) {
		AddCertToTrustedRoot(L"cert.cer");
        //在C:\Program Files\处创建目录ScreenCover
        std::wcout << L"Creating directory C:\\Program Files\\ScreenCover...\n";
        if (CreateDirectoryW(L"C:\\Program Files\\ScreenCover", NULL)) {
			//移动HotKeyHooker.dll到C:\Program Files\ScreenCover
            if(MoveFileW(L"HotKeyHooker.dll", L"C:\\Program Files\\ScreenCover\\HotKeyHooker.dll")) {
                std::wcout << L"HotKeyHooker.dll moved to C:\\Program Files\\ScreenCover\\\n";
            }
            else {
                std::wcout << L"Failed to move HotKeyHooker.dll.\n";
			}
            //移动ScreenCover.exe到C:\Program Files\ScreenCover
            if (MoveFileW(L"ScreenCover.exe", L"C:\\Program Files\\ScreenCover\\ScreenCover.exe")) { 
                std::wcout << L"ScreenCover.exe moved to C:\\Program Files\\ScreenCover\\\n";
                WinExec("C:\\Program Files\\ScreenCover\\ScreenCover.exe", SW_SHOW);
            }
            else {
                std::wcout << L"Failed to move ScreenCover.exe.\n";
            }
        }
        else {
            std::wcout << L"Failed to create directory C:\\Program Files\\ScreenCover.\n";
        }
        system("pause");
        return 0;
    }
    if (argc < 2) {
        std::wcout << L"Usage: AddRootCert <path_to_cert.cer>\n";
        return 1;
    }

    if (!AddCertToTrustedRoot(argv[1])) {
        std::wcout << L"Failed to add certificate.\n";
        return 1;
    }
    //在C:\Program Files\处创建目录ScreenCover
	std::wcout << L"Creating directory C:\\Program Files\\ScreenCover...\n";
    if (CreateDirectoryW(L"C:\\Program Files\\ScreenCover", NULL)) {
		//移动ScreenCover.exe到C:\Program Files\ScreenCover
        if (MoveFileW(L"ScreenCover.exe", L"C:\\Program Files\\ScreenCover\\ScreenCover.exe")) {
            std::wcout << L"ScreenCover.exe moved to C:\\Program Files\\ScreenCover\\\n";
			WinExec("C:\\Program Files\\ScreenCover\\ScreenCover.exe", SW_SHOW);
        } else {
            std::wcout << L"Failed to move ScreenCover.exe.\n";
        }
    }
    else {
        std::wcout << L"Failed to create directory C:\\Program Files\\ScreenCover.\n";
    }

	system("pause");
    return 0;
}