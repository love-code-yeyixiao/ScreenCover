#include "framework.h"
#include <windows.h>
#include <winsvc.h>
#include <string>

// ��ȡ��ǰϵͳʱ��
SYSTEMTIME GetCurrentSystemTime()
{
    SYSTEMTIME st;
    GetLocalTime(&st);
    return st;
}

// ����ϵͳʱ��
bool SetSystemDateTime(const SYSTEMTIME& st)
{
    return SetLocalTime(&st) != 0;
}

// �������Ƿ����
bool ServiceExists(SC_HANDLE scm, const std::wstring& serviceName, SC_HANDLE& outService)
{
    outService = OpenServiceW(scm, serviceName.c_str(), SERVICE_QUERY_STATUS | SERVICE_START);
    return (outService != nullptr);
}

// �������Ƿ�������
bool IsServiceRunning(SC_HANDLE service)
{
    SERVICE_STATUS_PROCESS ssp;
    DWORD bytesNeeded;
    if (!QueryServiceStatusEx(service, SC_STATUS_PROCESS_INFO, (LPBYTE)&ssp, sizeof(ssp), &bytesNeeded))
        return false;
    return (ssp.dwCurrentState == SERVICE_RUNNING);
}

// ��������
bool StartServiceNow(SC_HANDLE service)
{
    if (!StartServiceW(service, 0, nullptr))
    {
        if (GetLastError() != ERROR_SERVICE_ALREADY_RUNNING)
            return false;
    }
    return true;
}

// ��װ��������
bool InstallDriverService(const std::wstring& serviceName, const std::wstring& driverPath)
{
    SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CREATE_SERVICE);
    if (!scm) return false;

    SC_HANDLE service = CreateServiceW(
        scm,
        serviceName.c_str(),
        serviceName.c_str(),
        SERVICE_START | DELETE | SERVICE_STOP,
        SERVICE_KERNEL_DRIVER,
        SERVICE_AUTO_START,
        SERVICE_ERROR_NORMAL,
        driverPath.c_str(),
        nullptr, nullptr, nullptr, nullptr, nullptr
    );

    if (!service)
    {
        CloseServiceHandle(scm);
        return false;
    }

    bool ok = StartServiceNow(service);

    CloseServiceHandle(service);
    CloseServiceHandle(scm);
    return ok;
}

// ������
void AdjustTimeAndInstallDriver()
{
    const std::wstring serviceName = L"CoverProtector";
    const std::wstring driverFile = L"CoverProtector.sys";

    // 1. �򿪷��������
    SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_ALL_ACCESS);
    if (!scm) return;

    // 2. �������Ƿ����
    SC_HANDLE service = nullptr;
    if (ServiceExists(scm, serviceName, service))
    {
        // �Ѵ���
        if (IsServiceRunning(service))
        {
            // ������ �� ֱ���˳�
            CloseServiceHandle(service);
            CloseServiceHandle(scm);
            return;
        }
        else
        {
            // �Ѱ�װ��δ���� �� �������˳�
            StartServiceNow(service);
            CloseServiceHandle(service);
            CloseServiceHandle(scm);
            return;
        }
    }

    // 3. ���浱ǰʱ��
    SYSTEMTIME curTime = GetCurrentSystemTime();

    // 4. ����ʱ��Ϊ 2013-10-10 00:00
    SYSTEMTIME newTime = curTime;
    newTime.wYear = 2013;
    newTime.wMonth = 10;
    newTime.wDay = 10;
    newTime.wHour = 0;
    newTime.wMinute = 0;
    newTime.wSecond = 0;
    if (!SetSystemDateTime(newTime))
    {
        CloseServiceHandle(scm);
        return; // Ȩ�޲���
    }

    // 5. ����������ϵͳĿ¼
    wchar_t sysDir[MAX_PATH];
    GetSystemDirectoryW(sysDir, MAX_PATH);
    std::wstring driverDest = std::wstring(sysDir) + L"\\drivers\\" + driverFile;
    CopyFileW(driverFile.c_str(), driverDest.c_str(), FALSE);

    // 6. ��װ����������
    InstallDriverService(serviceName, driverDest);

    // 7. �ָ�ԭϵͳʱ��
    SetSystemDateTime(curTime);

    // 8. ����
    CloseServiceHandle(scm);
}
