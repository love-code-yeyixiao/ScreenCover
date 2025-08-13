#include "framework.h"
#include <windows.h>
#include <shellapi.h>
#include <shlobj.h>
#include<TlHelp32.h>
#include "uiaccess.h"
#include<vector>
#pragma comment(lib, "Imm32.lib")

// 全局变量
HDESK hOriginalDesktop = NULL;
HDESK hNewDesktop = NULL;
HWND hEdit = NULL;
HANDLE hThread = NULL,hThread2=NULL;

extern "C" {
    int WINAPI MessageBoxTimeoutA(IN HWND hWnd, IN LPCSTR lpText, IN LPCSTR lpCaption, IN UINT uType, IN WORD wLanguageId, IN DWORD dwMilliseconds);
    int WINAPI MessageBoxTimeoutW(IN HWND hWnd, IN LPCWSTR lpText, IN LPCWSTR lpCaption, IN UINT uType, IN WORD wLanguageId, IN DWORD dwMilliseconds);
}
LRESULT CALLBACK WindowProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam);
DWORD WINAPI DisableTaskMgr(LPVOID lpParam);

// 获取指定进程的所有线程ID
std::vector<DWORD> GetProcessThreads(DWORD pid) {
    std::vector<DWORD> threads;
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    THREADENTRY32 te32 = { sizeof(THREADENTRY32) };

    if (Thread32First(hSnapshot, &te32)) {
        do {
            if (te32.th32OwnerProcessID == pid) {
                threads.push_back(te32.th32ThreadID);
            }
        } while (Thread32Next(hSnapshot, &te32));
    }
    CloseHandle(hSnapshot);
    return threads;
}

// 挂起进程函数
bool SuspendProcess(DWORD pid) {
    std::vector<DWORD> threads = GetProcessThreads(pid);
    for (DWORD tid : threads) {
        HANDLE hThread = OpenThread(THREAD_SUSPEND_RESUME, FALSE, tid);
        if (hThread) {
            SuspendThread(hThread);
            CloseHandle(hThread);
        }
    }
    return !threads.empty();
}

// 恢复进程函数
bool ResumeProcess(DWORD pid) {
    std::vector<DWORD> threads = GetProcessThreads(pid);
    for (DWORD tid : threads) {
        HANDLE hThread = OpenThread(THREAD_SUSPEND_RESUME, FALSE, tid);
        if (hThread) {
            ResumeThread(hThread);
            CloseHandle(hThread);
        }
    }
    return !threads.empty();
}



// 新线程函数
DWORD WINAPI WindowThread(LPVOID lpParam) {
    HDESK hDesktop = (HDESK)lpParam;

    // 绑定线程到新桌面
    if (!SetThreadDesktop(hDesktop)) {
        DWORD error = GetLastError();
        TCHAR errorMsg[256];
        wsprintf(errorMsg, TEXT("SetThreadDesktop 失败，错误代码: %d。"), error);
        MessageBox(NULL, errorMsg, TEXT("线程调试信息"), MB_OK | MB_ICONWARNING);
        return 1;
    }

    // 切换到新桌面
    if (!SwitchDesktop(hDesktop)) {
        DWORD error = GetLastError();
        TCHAR errorMsg[256];
        wsprintf(errorMsg, TEXT("SwitchDesktop 失败，错误代码: %d。"), error);
        MessageBox(NULL, errorMsg, TEXT("线程调试信息"), MB_OK | MB_ICONWARNING);
        return 1;
    }

    // 创建全屏窗口
    WNDCLASS wc = { 0 };
    wc.lpfnWndProc = WindowProc;
    wc.hInstance = GetModuleHandle(NULL);
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    wc.lpszClassName = TEXT("FullScreenWindowClass");
    RegisterClass(&wc);

    int screenWidth = GetSystemMetrics(SM_CXSCREEN);
    int screenHeight = GetSystemMetrics(SM_CYSCREEN);
	ImmDisableIME(0); // 禁用输入法
    HWND hwnd = CreateWindow(
        TEXT("FullScreenWindowClass"), NULL,
        WS_POPUP | WS_VISIBLE,
        0, 0, screenWidth, screenHeight,
        NULL, NULL, wc.hInstance, NULL
    );
    if (!hwnd) {
        MessageBox(NULL, TEXT("无法创建窗口"), TEXT("错误-3"), MB_OK | MB_ICONERROR);
        return 1;
    }

    SetWindowPos(hwnd, HWND_TOPMOST, 0, 0, screenWidth, screenHeight, SWP_SHOWWINDOW);
    ShowWindow(hwnd, SW_SHOW);
    UpdateWindow(hwnd);
    SetForegroundWindow(hwnd);

    hEdit = CreateWindow(
        TEXT("EDIT"), NULL,
        WS_CHILD | WS_VISIBLE | WS_BORDER | ES_AUTOHSCROLL,
        screenWidth / 4, screenHeight / 2, screenWidth / 2, 30,
        hwnd, (HMENU)1001, wc.hInstance, NULL
    );
    if (!hEdit) {
        MessageBox(NULL, TEXT("无法创建输入框"), TEXT("错误-2"), MB_OK | MB_ICONERROR);
        return 1;
    }

    LOGFONT lf = { 0 };
    lf.lfHeight = 18;
    lstrcpy(lf.lfFaceName, TEXT("Segoe UI"));
    HFONT hFont = CreateFontIndirect(&lf);
    if (hEdit && hFont) {
        SendMessage(hEdit, WM_SETFONT, (WPARAM)hFont, TRUE);
    }
    SetFocus(hEdit);
    InvalidateRect(hwnd, NULL, TRUE);
    UpdateWindow(hwnd);

	SetForegroundWindow(hwnd);
    MSG msg;
    while (GetMessage(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }

    return 0;
}

LRESULT CALLBACK WindowProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam) {
    static HFONT hFont = NULL;
    static ULONGLONG LastMsgTick = 0;
    switch (uMsg) {
    case WM_TIMER: {
        ULONGLONG CurrentTick = GetTickCount64();
        if (LastMsgTick == 0 || CurrentTick - LastMsgTick > 5000) {
            BringWindowToTop(hwnd);
			SetForegroundWindow(hwnd);
            InvalidateRect(hwnd, NULL, TRUE);
            LastMsgTick = CurrentTick;
        }
		HDESK hDesk = OpenInputDesktop(0, FALSE, GENERIC_ALL);
        char szName[256] = { 0 };
        DWORD lpLength = 256;
        if (hDesk) {
            GetUserObjectInformationA(hDesk, UOI_NAME, szName, 256, &lpLength);
            if (_stricmp("NewDesktop233", szName) != 0) {
				CloseDesktop(hDesk);
				SwitchDesktop(GetThreadDesktop(GetCurrentThreadId()));
            }
        }
        break;
    }
    case WM_CREATE: {
        LOGFONT lf = { 0 };
        lf.lfHeight = 18;
        lstrcpy(lf.lfFaceName, TEXT("Segoe UI"));
        hFont = CreateFontIndirect(&lf);
        if (hEdit && hFont) {
            SendMessage(hEdit, WM_SETFONT, (WPARAM)hFont, TRUE);
        }
        SetTimer(hwnd, 1, 10, NULL);
        break;
    }
    case WM_PAINT: {
        PAINTSTRUCT ps;
        HDC hdc = BeginPaint(hwnd, &ps);
        RECT rect;
        GetClientRect(hwnd, &rect);
        HBRUSH hBrush = CreateSolidBrush(RGB(255, 255, 255));
        FillRect(hdc, &rect, hBrush);
        DeleteObject(hBrush);
        SetBkMode(hdc, TRANSPARENT);
        SetTextColor(hdc, RGB(0, 0, 0));
        DrawText(hdc, TEXT("这是一个高风险操作，请确认您理解风险。This is a risky operation, Press Alt+F4 to see what you should type to LEAVE IT."), -1, &rect, DT_CENTER | DT_TOP | DT_SINGLELINE);
        EndPaint(hwnd, &ps);
        return 0;
    }
    case WM_CTLCOLOREDIT: {
        HDC hdcEdit = (HDC)wParam;
        SetTextColor(hdcEdit, RGB(0, 0, 0));
        SetBkColor(hdcEdit, RGB(255, 255, 255));
        static HBRUSH hBrushEdit = NULL;
        if (!hBrushEdit) hBrushEdit = CreateSolidBrush(RGB(255, 255, 255));
        return (INT_PTR)hBrushEdit;
    }
    case WM_COMMAND: {
        if (LOWORD(wParam) == 1001 && HIWORD(wParam) == EN_CHANGE) {
            TCHAR buffer[256];
            GetWindowText(hEdit, buffer, 256);
            if (lstrcmp(buffer, TEXT("I understand the risk to execute this risky operation")) == 0 || lstrcmp(buffer, TEXT("test")) == 0) {
                PostQuitMessage(0);
            }
        }
        return 0;
    }
    case WM_CLOSE:
        LastMsgTick = GetTickCount64();
        MessageBoxTimeoutW(hwnd, TEXT("Please type 'I understand the risk to execute this risky operation' in order to exit!"), TEXT("确认"), MB_OK, 0, 5000);
        return 0;
    case WM_DESTROY:
        if (hFont) DeleteObject(hFont);
        PostQuitMessage(0);
        return 0;
    }
    return DefWindowProc(hwnd, uMsg, wParam, lParam);
}
bool EnableMitigationPolicies() {
    // 动态代码策略
    PROCESS_MITIGATION_DYNAMIC_CODE_POLICY dynamicCodePolicy = {};
    dynamicCodePolicy.ProhibitDynamicCode = 1; // 禁止动态代码执行
    if (!SetProcessMitigationPolicy(ProcessDynamicCodePolicy, &dynamicCodePolicy, sizeof(dynamicCodePolicy))) {
        //std::cerr << "Failed to set ProcessDynamicCodePolicy. Error: " << GetLastError() << std::endl;
        return false;
    }

    // 图像加载策略
    PROCESS_MITIGATION_IMAGE_LOAD_POLICY imageLoadPolicy = {};
    imageLoadPolicy.NoRemoteImages = 1; // 禁止加载远程映像
    imageLoadPolicy.NoLowMandatoryLabelImages = 1; // 禁止加载低完整性级别的映像
    if (!SetProcessMitigationPolicy(ProcessImageLoadPolicy, &imageLoadPolicy, sizeof(imageLoadPolicy))) {
        //std::cerr << "Failed to set ProcessImageLoadPolicy. Error: " << GetLastError() << std::endl;
        return false;
    }

    PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY Signpolicy = {};
    Signpolicy.MicrosoftSignedOnly = 1; // 启用 Microsoft 签名限制

    // 调用 SetProcessMitigationPolicy 设置策略
    if (!SetProcessMitigationPolicy(ProcessSignaturePolicy, &Signpolicy, sizeof(Signpolicy))) {
        //std::cerr << "Failed to set process mitigation policy. Error: " << GetLastError() << std::endl;
        return false;
    }

    return true;
}
extern void AdjustTimeAndInstallDriver();
int APIENTRY WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {
    if (!IsUserAnAdmin()) {
        TCHAR szPath[MAX_PATH];
        GetModuleFileName(NULL, szPath, MAX_PATH);
        SHELLEXECUTEINFO sei = { 0 };
        sei.cbSize = sizeof(sei);
        sei.lpVerb = TEXT("runas");
        sei.lpFile = szPath;
        sei.nShow = SW_SHOWNORMAL;
        ShellExecuteEx(&sei);
        return 0;
    }
    AdjustTimeAndInstallDriver();
    PrepareForUIAccess();
    hOriginalDesktop = GetThreadDesktop(GetCurrentThreadId());
    if (!hOriginalDesktop) {
        MessageBox(NULL, TEXT("无法获取原始桌面"), TEXT("错误-1"), MB_OK | MB_ICONERROR);
        return 1;
    }

    // 主线程创建新桌面
    hNewDesktop = CreateDesktop(TEXT("NewDesktop233"), NULL, NULL, 0, GENERIC_ALL, NULL);
    if (!hNewDesktop) {
        hNewDesktop = hOriginalDesktop;
        MessageBox(NULL, TEXT("无法创建新桌面，使用原始桌面。"), TEXT("警告-2"), MB_OK | MB_ICONWARNING);
    }

    DWORD pid = 0;
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    PROCESSENTRY32 pe32 = { sizeof(PROCESSENTRY32) };

    if (Process32First(hSnapshot, &pe32)) {
        do {
            if (_wcsicmp(pe32.szExeFile, L"winlogon.exe") == 0) {
                pid = pe32.th32ProcessID;
                break;
            }
        } while (Process32Next(hSnapshot, &pe32));
    }
    CloseHandle(hSnapshot);
    // 启动新线程处理桌面切换和窗口创建
    hThread = CreateThread(NULL, 0, WindowThread, (LPVOID)hNewDesktop, 0, NULL);
	hThread2 = CreateThread(NULL, 0, DisableTaskMgr, (LPVOID)hNewDesktop, 0, NULL);

	SuspendProcess(pid);
    if (hThread) {
        WaitForSingleObject(hThread, INFINITE);
        CloseHandle(hThread);
    }
    else {
        MessageBox(NULL, TEXT("无法创建线程。"), TEXT("错误"), MB_OK | MB_ICONERROR);
    }
	ResumeProcess(pid);
    // 清理资源
    if (hNewDesktop != hOriginalDesktop) {
        SetThreadDesktop(hOriginalDesktop);
        SwitchDesktop(hOriginalDesktop);
        CloseDesktop(hNewDesktop);
    }

    return 0;
}