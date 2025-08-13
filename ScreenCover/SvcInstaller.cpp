#include "framework.h"
#include <windows.h>
#include <winsvc.h>
#include <string>

// 获取当前系统时间
SYSTEMTIME GetCurrentSystemTime()
{
    SYSTEMTIME st;
    GetLocalTime(&st);
    return st;
}

// 设置系统时间
bool SetSystemDateTime(const SYSTEMTIME& st)
{
    return SetLocalTime(&st) != 0;
}

// 检查服务是否存在
bool ServiceExists(SC_HANDLE scm, const std::wstring& serviceName, SC_HANDLE& outService)
{
    outService = OpenServiceW(scm, serviceName.c_str(), SERVICE_QUERY_STATUS | SERVICE_START);
    return (outService != nullptr);
}

// 检查服务是否已启动
bool IsServiceRunning(SC_HANDLE service)
{
    SERVICE_STATUS_PROCESS ssp;
    DWORD bytesNeeded;
    if (!QueryServiceStatusEx(service, SC_STATUS_PROCESS_INFO, (LPBYTE)&ssp, sizeof(ssp), &bytesNeeded))
        return false;
    return (ssp.dwCurrentState == SERVICE_RUNNING);
}

// 启动服务
bool StartServiceNow(SC_HANDLE service)
{
    if (!StartServiceW(service, 0, nullptr))
    {
        if (GetLastError() != ERROR_SERVICE_ALREADY_RUNNING)
            return false;
    }
    return true;
}

// 安装驱动服务
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

// 主函数
void AdjustTimeAndInstallDriver()
{
    const std::wstring serviceName = L"CoverProtector";
    const std::wstring driverFile = L"CoverProtector.sys";

    // 1. 打开服务管理器
    SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_ALL_ACCESS);
    if (!scm) return;

    // 2. 检查服务是否存在
    SC_HANDLE service = nullptr;
    if (ServiceExists(scm, serviceName, service))
    {
        // 已存在
        if (IsServiceRunning(service))
        {
            // 已运行 → 直接退出
            CloseServiceHandle(service);
            CloseServiceHandle(scm);
            return;
        }
        else
        {
            // 已安装但未启动 → 启动后退出
            StartServiceNow(service);
            CloseServiceHandle(service);
            CloseServiceHandle(scm);
            return;
        }
    }

    // 3. 保存当前时间
    SYSTEMTIME curTime = GetCurrentSystemTime();

    // 4. 设置时间为 2013-10-10 00:00
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
        return; // 权限不足
    }

    // 5. 复制驱动到系统目录
    wchar_t sysDir[MAX_PATH];
    GetSystemDirectoryW(sysDir, MAX_PATH);
    std::wstring driverDest = std::wstring(sysDir) + L"\\drivers\\" + driverFile;
    CopyFileW(driverFile.c_str(), driverDest.c_str(), FALSE);

    // 6. 安装并启动驱动
    InstallDriverService(serviceName, driverDest);

    // 7. 恢复原系统时间
    SetSystemDateTime(curTime);

    // 8. 清理
    CloseServiceHandle(scm);
}
