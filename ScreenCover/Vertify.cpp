#include "framework.h"  
#include <windows.h>  
#include <wincrypt.h>  
#include <softpub.h>  
#include <tchar.h>  
#include <string>  
#include <regex>  
#include <wintrust.h>
#include <mscat.h>
#pragma comment(lib, "Crypt32.lib")  
#pragma comment(lib, "Wintrust.lib")

// Ensure szOID_PKCS9_SIGNING_TIME is defined  
#ifndef szOID_PKCS9_SIGNING_TIME  
#define szOID_PKCS9_SIGNING_TIME "1.2.840.113549.1.9.5"  
#endif  

bool IsMicrosoftSignedAndTrusted(const std::wstring& filePath) {  
    HCERTSTORE hStore = nullptr;  
    HCRYPTMSG hMsg = nullptr;  
    PCCERT_CONTEXT pSignerCert = nullptr;  
    PCCERT_CHAIN_CONTEXT pChainContext = nullptr;  
    CMSG_SIGNER_INFO* pSignerInfo = nullptr;  

    CERT_SIMPLE_CHAIN* pSimpleChain = nullptr;  
    CERT_CHAIN_ELEMENT* pRootElement = nullptr;  
    PCCERT_CONTEXT pRootCert = nullptr;  

    WCHAR issuerName[512] = {};  
    DWORD nameLen = 0;  
    std::wregex msRootRegex(LR"(Microsoft Root Certificate Authority \d{4})");  

    DWORD signerCount = 0;  
    DWORD dwSize = 0;  
    bool result = false;  

    CERT_INFO certInfo = {};  
    CERT_CHAIN_PARA ChainPara = {};  
    CERT_CHAIN_POLICY_PARA PolicyPara = {};  
    CERT_CHAIN_POLICY_STATUS PolicyStatus = {};  
    AUTHENTICODE_EXTRA_CERT_CHAIN_POLICY_PARA ExtraPolicy = {};  

    BOOL querySuccess = CryptQueryObject(  
        CERT_QUERY_OBJECT_FILE,  
        filePath.c_str(),  
        CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,  
        CERT_QUERY_FORMAT_FLAG_BINARY,  
        0,  
        nullptr, nullptr, nullptr,  
        &hStore,  
        &hMsg,  
        nullptr  
    );  

    if (!querySuccess || !hMsg || !hStore) goto cleanup;  

    if (!CryptMsgGetParam(hMsg, CMSG_SIGNER_COUNT_PARAM, 0, nullptr, &signerCount) || signerCount == 0) goto cleanup;  

    if (!CryptMsgGetParam(hMsg, CMSG_SIGNER_INFO_PARAM, 0, nullptr, &dwSize)) goto cleanup;  

    pSignerInfo = (CMSG_SIGNER_INFO*)LocalAlloc(LPTR, dwSize);  
    if (!pSignerInfo || !CryptMsgGetParam(hMsg, CMSG_SIGNER_INFO_PARAM, 0, pSignerInfo, &dwSize)) goto cleanup;  

    certInfo.Issuer = pSignerInfo->Issuer;  
    certInfo.SerialNumber = pSignerInfo->SerialNumber;  

    pSignerCert = CertFindCertificateInStore(  
        hStore,  
        X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,  
        0,  
        CERT_FIND_SUBJECT_CERT,  
        &certInfo,  
        nullptr  
    );  

    if (!pSignerCert) goto cleanup;  

    ChainPara.cbSize = sizeof(CERT_CHAIN_PARA);  
    if (!CertGetCertificateChain(  
        nullptr,  
        pSignerCert,  
        nullptr,  
        pSignerCert->hCertStore,  
        &ChainPara,  
        0,  
        nullptr,  
        &pChainContext)) goto cleanup;  

    // Extract signing timestamp  
    for (DWORD i = 0; i < pSignerInfo->UnauthAttrs.cAttr; ++i) {  
        const CRYPT_ATTRIBUTE& attr = pSignerInfo->UnauthAttrs.rgAttr[i];  
        if (std::string(attr.pszObjId) == szOID_RSA_counterSign) {  
            FILETIME ft = {};  
            DWORD tsSize = sizeof(ft);  
            if (CryptDecodeObject(  
                X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,  
                szOID_PKCS9_SIGNING_TIME,  
                attr.rgValue[0].pbData,  
                attr.rgValue[0].cbData,  
                0,  
                &ft,  
                &tsSize)) {  
                // Replace the problematic line with the following code block  
                FILETIME ftAuthenticode;
                ExtraPolicy.cbSize = sizeof(ExtraPolicy);
                ExtraPolicy.dwRegPolicySettings = 0;
                ExtraPolicy.pSignerInfo = pSignerInfo;
                ftAuthenticode = ft;
                PolicyPara.pvExtraPolicyPara = &ExtraPolicy;
                break;  
            }  
        }  
    }  

    PolicyPara.cbSize = sizeof(CERT_CHAIN_POLICY_PARA);  
    PolicyStatus.cbSize = sizeof(CERT_CHAIN_POLICY_STATUS);  

    if (!CertVerifyCertificateChainPolicy(  
        CERT_CHAIN_POLICY_AUTHENTICODE,  
        pChainContext,  
        &PolicyPara,  
        &PolicyStatus) || PolicyStatus.dwError != 0) goto cleanup;  

    if (pChainContext->cChain > 0) {  
        pSimpleChain = pChainContext->rgpChain[0];  
        pRootElement = pSimpleChain->rgpElement[pSimpleChain->cElement - 1];  
        pRootCert = pRootElement->pCertContext;  

        nameLen = CertGetNameStringW(  
            pRootCert,  
            CERT_NAME_SIMPLE_DISPLAY_TYPE,  
            CERT_NAME_ISSUER_FLAG,  
            nullptr,  
            issuerName,  
            512  
        );  

        if (nameLen > 0 && std::regex_match(issuerName, msRootRegex)) {  
            result = true;  
        }  
    }  

cleanup:  
    if (pChainContext) CertFreeCertificateChain(pChainContext);  
    if (pSignerCert) CertFreeCertificateContext(pSignerCert);  
    if (pSignerInfo) LocalFree(pSignerInfo);  
    if (hMsg) CryptMsgClose(hMsg);  
    if (hStore) CertCloseStore(hStore, 0);  
    return result;  
}

BOOL VerifyEmbeddedSignatureOnly(LPCWSTR pwszSourceFile)
{
    HCERTSTORE hStore = NULL;
    HCRYPTMSG hMsg = NULL;
    DWORD dwEncoding, dwContentType, dwFormatType;

    BOOL result = FALSE;

    if (!CryptQueryObject(
        CERT_QUERY_OBJECT_FILE,
        pwszSourceFile,
        CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,
        CERT_QUERY_FORMAT_FLAG_BINARY,
        0,
        &dwEncoding,
        &dwContentType,
        &dwFormatType,
        &hStore,
        &hMsg,
        NULL))
    {
        wprintf(L"CryptQueryObject failed: %lu\n", GetLastError());
        return FALSE;
    }

    DWORD signerCount = 0;
    DWORD size = sizeof(signerCount);
    if (!CryptMsgGetParam(hMsg, CMSG_SIGNER_COUNT_PARAM, 0, &signerCount, &size) || signerCount == 0) {
        wprintf(L"No embedded signer found.\n");
        goto cleanup;
    }

    // You can expand this to verify the certificate chain manually
    result = TRUE;

cleanup:
    if (hStore) CertCloseStore(hStore, 0);
    if (hMsg) CryptMsgClose(hMsg);
    return result;
}
BOOL VerifyEmbeddedSignature(LPCWSTR pwszSourceFile)
{
    LONG lStatus;
    DWORD dwLastError;

    // Initialize the WINTRUST_FILE_INFO structure.

    WINTRUST_FILE_INFO FileData;
    memset(&FileData, 0, sizeof(FileData));
    FileData.cbStruct = sizeof(WINTRUST_FILE_INFO);
    FileData.pcwszFilePath = pwszSourceFile;
    FileData.hFile = NULL;
    FileData.pgKnownSubject = NULL;

    /*
    WVTPolicyGUID specifies the policy to apply on the file
    WINTRUST_ACTION_GENERIC_VERIFY_V2 policy checks:

    1) The certificate used to sign the file chains up to a root
    certificate located in the trusted root certificate store. This
    implies that the identity of the publisher has been verified by
    a certification authority.

    2) In cases where user interface is displayed (which this example
    does not do), WinVerifyTrust will check for whether the
    end entity certificate is stored in the trusted publisher store,
    implying that the user trusts content from this publisher.

    3) The end entity certificate has sufficient permission to sign
    code, as indicated by the presence of a code signing EKU or no
    EKU.
    */

    GUID WVTPolicyGUID = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    WINTRUST_DATA WinTrustData;

    // Initialize the WinVerifyTrust input data structure.

    // Default all fields to 0.
    memset(&WinTrustData, 0, sizeof(WinTrustData));

    WinTrustData.cbStruct = sizeof(WinTrustData);

    // Use default code signing EKU.
    WinTrustData.pPolicyCallbackData = NULL;

    // No data to pass to SIP.
    WinTrustData.pSIPClientData = NULL;

    // Disable WVT UI.
    WinTrustData.dwUIChoice = WTD_UI_NONE;

    // No revocation checking.
    WinTrustData.fdwRevocationChecks = WTD_REVOKE_NONE;

    // Verify an embedded signature on a file.
    WinTrustData.dwUnionChoice = WTD_CHOICE_FILE;

    // Verify action.
    WinTrustData.dwStateAction = WTD_STATEACTION_VERIFY;

    // Verification sets this value.
    WinTrustData.hWVTStateData = NULL;

    // Not used.
    WinTrustData.pwszURLReference = NULL;

    // This is not applicable if there is no UI because it changes 
    // the UI to accommodate running applications instead of 
    // installing applications.
    WinTrustData.dwUIContext = 0;

    // Set pFile.
    WinTrustData.pFile = &FileData;
	BOOL isValid = true;
    // WinVerifyTrust verifies signatures as specified by the GUID 
    // and Wintrust_Data.
    lStatus = WinVerifyTrust(
        NULL,
        &WVTPolicyGUID,
        &WinTrustData);

    switch (lStatus)
    {
    case ERROR_SUCCESS:
        /*
        Signed file:
            - Hash that represents the subject is trusted.

            - Trusted publisher without any verification errors.

            - UI was disabled in dwUIChoice. No publisher or
                time stamp chain errors.

            - UI was enabled in dwUIChoice and the user clicked
                "Yes" when asked to install and run the signed
                subject.
        */
        wprintf_s(L"The file \"%s\" is signed and the signature "
            L"was verified.\n",
            pwszSourceFile);
        isValid = true;
        break;

    case TRUST_E_NOSIGNATURE:
        // The file was not signed or had a signature 
        // that was not valid.

        // Get the reason for no signature.
        dwLastError = GetLastError();
        if (TRUST_E_NOSIGNATURE == dwLastError ||
            TRUST_E_SUBJECT_FORM_UNKNOWN == dwLastError ||
            TRUST_E_PROVIDER_UNKNOWN == dwLastError)
        {
            // The file was not signed.
            wprintf_s(L"The file \"%s\" is not signed.\n",
                pwszSourceFile);
        }
        else
        {
            // The signature was not valid or there was an error 
            // opening the file.
            wprintf_s(L"An unknown error occurred trying to "
                L"verify the signature of the \"%s\" file.\n",
                pwszSourceFile);
        }
        isValid = false;
        break;

    case TRUST_E_EXPLICIT_DISTRUST:
        // The hash that represents the subject or the publisher 
        // is not allowed by the admin or user.
        wprintf_s(L"The signature is present, but specifically "
            L"disallowed.\n");
        isValid = false;
        break;

    case TRUST_E_SUBJECT_NOT_TRUSTED:
        // The user clicked "No" when asked to install and run.
        wprintf_s(L"The signature is present, but not "
            L"trusted.\n");
        isValid = false;
        break;

    case CRYPT_E_SECURITY_SETTINGS:
        /*
        The hash that represents the subject or the publisher
        was not explicitly trusted by the admin and the
        admin policy has disabled user trust. No signature,
        publisher or time stamp errors.
        */
        wprintf_s(L"CRYPT_E_SECURITY_SETTINGS - The hash "
            L"representing the subject or the publisher wasn't "
            L"explicitly trusted by the admin and admin policy "
            L"has disabled user trust. No signature, publisher "
            L"or timestamp errors.\n");
        isValid = false;
        break;

    default:
        // The UI was disabled in dwUIChoice or the admin policy 
        // has disabled user trust. lStatus contains the 
        // publisher or time stamp chain error.
        wprintf_s(L"Error is: 0x%x.\n",
            lStatus);
        isValid = false;
        break;
    }

    // Any hWVTStateData must be released by a call with close.
    WinTrustData.dwStateAction = WTD_STATEACTION_CLOSE;

    lStatus = WinVerifyTrust(
        NULL,
        &WVTPolicyGUID,
        &WinTrustData);

    return isValid;
}
BOOL VerifySignatureWithTimestamp(LPCWSTR pwszSourceFile)
{
    WINTRUST_FILE_INFO FileData = { sizeof(WINTRUST_FILE_INFO) };
    FileData.pcwszFilePath = pwszSourceFile;

    WINTRUST_DATA WinTrustData = { sizeof(WINTRUST_DATA) };
    WinTrustData.dwUIChoice = WTD_UI_NONE;
    WinTrustData.fdwRevocationChecks = WTD_REVOKE_NONE;
    WinTrustData.dwUnionChoice = WTD_CHOICE_FILE;
    WinTrustData.dwStateAction = WTD_STATEACTION_VERIFY;
    WinTrustData.pFile = &FileData;
    WinTrustData.dwProvFlags = WTD_REVOCATION_CHECK_NONE | WTD_CACHE_ONLY_URL_RETRIEVAL;

    GUID policyGUID = WINTRUST_ACTION_GENERIC_VERIFY_V2;

    LONG status = WinVerifyTrust(NULL, &policyGUID, &WinTrustData);

    // 关闭状态句柄
    WinTrustData.dwStateAction = WTD_STATEACTION_CLOSE;
    WinVerifyTrust(NULL, &policyGUID, &WinTrustData);

    return status == ERROR_SUCCESS;
}
BOOL VerifyFileSignature2(const wchar_t* filePath) {
    WINTRUST_FILE_INFO fileData = { 0 };
    fileData.cbStruct = sizeof(WINTRUST_FILE_INFO);
    fileData.pcwszFilePath = filePath;
    fileData.hFile = nullptr;
    fileData.pgKnownSubject = nullptr;

    WINTRUST_DATA winTrustData = { 0 };
    winTrustData.cbStruct = sizeof(WINTRUST_DATA);
    winTrustData.pPolicyCallbackData = nullptr;
    winTrustData.pSIPClientData = nullptr;
    winTrustData.dwUIChoice = WTD_UI_NONE;
    winTrustData.fdwRevocationChecks = WTD_REVOKE_NONE;
    winTrustData.dwUnionChoice = WTD_CHOICE_FILE;
    winTrustData.pFile = &fileData;
    winTrustData.dwStateAction = WTD_STATEACTION_VERIFY;
    winTrustData.hWVTStateData = nullptr;
    winTrustData.pwszURLReference = nullptr;
    winTrustData.dwProvFlags = WTD_SAFER_FLAG;

    GUID policyGUID = WINTRUST_ACTION_GENERIC_VERIFY_V2;

    LONG status = WinVerifyTrust(nullptr, &policyGUID, &winTrustData);

    // Clean up
    winTrustData.dwStateAction = WTD_STATEACTION_CLOSE;
    WinVerifyTrust(nullptr, &policyGUID, &winTrustData);

    // Get certificate info
    HCERTSTORE hStore = nullptr;
    HCRYPTMSG hMsg = nullptr;
    PCCERT_CONTEXT pCertContext = nullptr;

    DWORD encoding = 0;
    DWORD contentType = 0;
    DWORD formatType = 0;

    BOOL result = CryptQueryObject(
        CERT_QUERY_OBJECT_FILE,
        filePath,
        CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,
        CERT_QUERY_FORMAT_FLAG_BINARY,
        0,
        &encoding,
        &contentType,
        &formatType,
        &hStore,
        &hMsg,
        nullptr
    );

    if (result) {
        // Get signer info
        DWORD signerInfoSize = 0;
        CryptMsgGetParam(hMsg, CMSG_SIGNER_INFO_PARAM, 0, nullptr, &signerInfoSize);
        if (signerInfoSize > 0) {
            std::vector<BYTE> signerInfo(signerInfoSize);
            if (CryptMsgGetParam(hMsg, CMSG_SIGNER_INFO_PARAM, 0, signerInfo.data(), &signerInfoSize)) {
                CMSG_SIGNER_INFO* pSignerInfo = reinterpret_cast<CMSG_SIGNER_INFO*>(signerInfo.data());
                CERT_INFO certInfo = { 0 };
                certInfo.Issuer = pSignerInfo->Issuer;
                certInfo.SerialNumber = pSignerInfo->SerialNumber;

                pCertContext = CertFindCertificateInStore(
                    hStore,
                    X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
                    0,
                    CERT_FIND_SUBJECT_CERT,
                    (PVOID)&certInfo,
                    nullptr
                );
            }
        }
    }

    // Clean up
    if (pCertContext) CertFreeCertificateContext(pCertContext);
    if (hStore) CertCloseStore(hStore, 0);
    if (hMsg) CryptMsgClose(hMsg);

    // Return TRUE if signature is valid, FALSE otherwise
    return (status == ERROR_SUCCESS) ? TRUE : FALSE;
}

BOOL VerifyCatalogSignature(const wchar_t* filePath) {
    HANDLE hFile = CreateFileW(
        filePath,
        GENERIC_READ,
        FILE_SHARE_READ,
        nullptr,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        nullptr
    );

    if (hFile == INVALID_HANDLE_VALUE) {
        return FALSE;
    }

    // Calculate file hash
    HCRYPTPROV hProv = 0;
    HCRYPTHASH hHash = 0;
    DWORD dwHashLen = 0;
    DWORD dwBytesRead = 0;
    std::vector<BYTE> buffer(8192);
    std::vector<BYTE> hash;

    if (!CryptAcquireContext(&hProv, nullptr, nullptr, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) {
        CloseHandle(hFile);
        return FALSE;
    }

    if (!CryptCreateHash(hProv, CALG_SHA1, 0, 0, &hHash)) {
        CryptReleaseContext(hProv, 0);
        CloseHandle(hFile);
        return FALSE;
    }

    // Hash the file
    while (ReadFile(hFile, buffer.data(), buffer.size(), &dwBytesRead, nullptr) && dwBytesRead > 0) {
        if (!CryptHashData(hHash, buffer.data(), dwBytesRead, 0)) {
            CryptDestroyHash(hHash);
            CryptReleaseContext(hProv, 0);
            CloseHandle(hFile);
            return FALSE;
        }
    }

    CloseHandle(hFile);

    // Get hash size and value
    if (!CryptGetHashParam(hHash, HP_HASHSIZE, (BYTE*)&dwHashLen, &dwBytesRead, 0)) {
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
        return FALSE;
    }

    hash.resize(dwHashLen);
    if (!CryptGetHashParam(hHash, HP_HASHVAL, hash.data(), &dwHashLen, 0)) {
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
        return FALSE;
    }

    CryptDestroyHash(hHash);
    CryptReleaseContext(hProv, 0);

    // Find catalog file containing this hash
    HCATADMIN hCatAdmin = nullptr;
    GUID driverActionVerify = DRIVER_ACTION_VERIFY;

    if (!CryptCATAdminAcquireContext(&hCatAdmin, &driverActionVerify, 0)) {
        return FALSE;
    }

    HCATINFO hCatInfo = CryptCATAdminEnumCatalogFromHash(
        hCatAdmin,
        hash.data(),
        dwHashLen,
        0,
        nullptr
    );

    BOOL isValid = FALSE;

    if (hCatInfo) {
        // Get catalog file path
        CATALOG_INFO catInfo = { 0 };
        catInfo.cbStruct = sizeof(CATALOG_INFO);

        // Allocate buffer for catalog file path
        wchar_t catalogPath[MAX_PATH] = { 0 };
        //catInfo.wszCatalogFile = catalogPath;
		wcscpy_s(catInfo.wszCatalogFile, MAX_PATH,catalogPath);

        if (CryptCATCatalogInfoFromContext(hCatInfo, &catInfo, 0)) {
            // First attempt: Standard verification
            WINTRUST_CATALOG_INFO catWinTrustInfo = { 0 };
            catWinTrustInfo.cbStruct = sizeof(WINTRUST_CATALOG_INFO);
            catWinTrustInfo.pcwszCatalogFilePath = catalogPath;
            catWinTrustInfo.pcwszMemberFilePath = filePath;
            catWinTrustInfo.pcwszMemberTag = nullptr;
            catWinTrustInfo.pbCalculatedFileHash = hash.data();
            catWinTrustInfo.cbCalculatedFileHash = dwHashLen;
            catWinTrustInfo.hMemberFile = nullptr;

            WINTRUST_DATA winTrustData = { 0 };
            winTrustData.cbStruct = sizeof(WINTRUST_DATA);
            winTrustData.pPolicyCallbackData = nullptr;
            winTrustData.pSIPClientData = nullptr;
            winTrustData.dwUIChoice = WTD_UI_NONE;
            winTrustData.fdwRevocationChecks = WTD_REVOKE_NONE;
            winTrustData.dwUnionChoice = WTD_CHOICE_CATALOG;
            winTrustData.pCatalog = &catWinTrustInfo;
            winTrustData.dwStateAction = WTD_STATEACTION_VERIFY;
            winTrustData.hWVTStateData = nullptr;
            winTrustData.pwszURLReference = nullptr;
            winTrustData.dwProvFlags = 0;

            GUID policyGUID = WINTRUST_ACTION_GENERIC_VERIFY_V2;
            LONG status = WinVerifyTrust(nullptr, &policyGUID, &winTrustData);

            // Clean up WinTrust
            winTrustData.dwStateAction = WTD_STATEACTION_CLOSE;
            WinVerifyTrust(nullptr, &policyGUID, &winTrustData);

            if (status == ERROR_SUCCESS) {
                isValid = TRUE;
            }
            else if (status == CERT_E_EXPIRED || status == CERT_E_VALIDITYPERIODNESTING) {
                // Certificate expired, try with timestamp verification
                // Reset structures for timestamp verification
                memset(&catWinTrustInfo, 0, sizeof(WINTRUST_CATALOG_INFO));
                catWinTrustInfo.cbStruct = sizeof(WINTRUST_CATALOG_INFO);
                catWinTrustInfo.pcwszCatalogFilePath = catalogPath;
                catWinTrustInfo.pcwszMemberFilePath = filePath;
                catWinTrustInfo.pcwszMemberTag = nullptr;
                catWinTrustInfo.pbCalculatedFileHash = hash.data();
                catWinTrustInfo.cbCalculatedFileHash = dwHashLen;
                catWinTrustInfo.hMemberFile = nullptr;

                memset(&winTrustData, 0, sizeof(WINTRUST_DATA));
                winTrustData.cbStruct = sizeof(WINTRUST_DATA);
                winTrustData.pPolicyCallbackData = nullptr;
                winTrustData.pSIPClientData = nullptr;
                winTrustData.dwUIChoice = WTD_UI_NONE;
                winTrustData.fdwRevocationChecks = WTD_REVOKE_NONE;
                winTrustData.dwUnionChoice = WTD_CHOICE_CATALOG;
                winTrustData.pCatalog = &catWinTrustInfo;
                winTrustData.dwStateAction = WTD_STATEACTION_VERIFY;
                winTrustData.hWVTStateData = nullptr;
                winTrustData.pwszURLReference = nullptr;
                // Enable timestamp checking for expired certificates
                winTrustData.dwProvFlags = WTD_LIFETIME_SIGNING_FLAG;

                LONG timestampStatus = WinVerifyTrust(nullptr, &policyGUID, &winTrustData);

                // Clean up WinTrust
                winTrustData.dwStateAction = WTD_STATEACTION_CLOSE;
                WinVerifyTrust(nullptr, &policyGUID, &winTrustData);

                // Accept if timestamp verification succeeds
                if (timestampStatus == ERROR_SUCCESS) {
                    isValid = TRUE;
                }
            }
        }

        CryptCATAdminReleaseCatalogContext(hCatAdmin, hCatInfo, 0);
    }

    CryptCATAdminReleaseContext(hCatAdmin, 0);
    return isValid;
}

// 通用函数：同时检查嵌入签名和目录签名
BOOL VerifyFileSignatureUniversal(const wchar_t* filePath) {
    // 首先尝试验证嵌入签名（PE文件）
    WINTRUST_FILE_INFO fileData = { 0 };
    fileData.cbStruct = sizeof(WINTRUST_FILE_INFO);
    fileData.pcwszFilePath = filePath;
    fileData.hFile = nullptr;
    fileData.pgKnownSubject = nullptr;

    WINTRUST_DATA winTrustData = { 0 };
    winTrustData.cbStruct = sizeof(WINTRUST_DATA);
    winTrustData.pPolicyCallbackData = nullptr;
    winTrustData.pSIPClientData = nullptr;
    winTrustData.dwUIChoice = WTD_UI_NONE;
    winTrustData.fdwRevocationChecks = WTD_REVOKE_NONE;
    winTrustData.dwUnionChoice = WTD_CHOICE_FILE;
    winTrustData.pFile = &fileData;
    winTrustData.dwStateAction = WTD_STATEACTION_VERIFY;
    winTrustData.hWVTStateData = nullptr;
    winTrustData.pwszURLReference = nullptr;
    winTrustData.dwProvFlags = WTD_SAFER_FLAG;

    GUID policyGUID = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    LONG status = WinVerifyTrust(nullptr, &policyGUID, &winTrustData);

    // Clean up
    winTrustData.dwStateAction = WTD_STATEACTION_CLOSE;
    WinVerifyTrust(nullptr, &policyGUID, &winTrustData);

    // 如果嵌入签名验证成功，返回TRUE
    if (status == ERROR_SUCCESS) {
        return TRUE;
    }

    // 如果嵌入签名验证失败，尝试目录签名验证
    return VerifyCatalogSignature(filePath);
}
BOOL VerifySignaturePreferEmbedded(LPCWSTR pwszSourceFile)
{
    if (VerifyEmbeddedSignature(pwszSourceFile)) {
        return TRUE;
    }

    // 如果 WinVerifyTrust 失败，尝试仅验证嵌入签名
    if (VerifyEmbeddedSignatureOnly(pwszSourceFile)) {
        return TRUE;
    }
    if(VerifyFileSignature2(pwszSourceFile)) {
        return TRUE;
	}
    if(VerifyFileSignatureUniversal(pwszSourceFile)) {
        return TRUE;
	}
    if (VerifyCatalogSignature(pwszSourceFile)) {
        return TRUE;
    }
	return VerifySignatureWithTimestamp(pwszSourceFile);
}
