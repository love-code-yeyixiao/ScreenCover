// dllmain.cpp : 定义 DLL 应用程序的入口点。
#include "framework.h"

#include <windows.h>
#include <stdio.h>

// 键盘钩子过程
HDESK hCurDesk = NULL;

// Dll所创建线程的句柄
HANDLE hThread = NULL;
// Dll所创建线程的ID
DWORD dwThreadId = 0;
// Dll所创建线程的线程函数
DWORD WINAPI ThreadFunc();

// 钩子句柄
HHOOK hHook = NULL;
// 低级键盘钩子回调函数
LRESULT CALLBACK KeyboardProc(int, WPARAM, LPARAM);

#define VK_L 0x4C

BOOL APIENTRY DllMain(HANDLE hMoudle, DWORD dwReason, LPVOID lpReserved)
{
    switch (dwReason)
    {
    case DLL_PROCESS_ATTACH:
        hThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)ThreadFunc, NULL, 0, &dwThreadId);
        break;
    case DLL_PROCESS_DETACH:
        // 卸载低级键盘钩子
        if (hHook != NULL)
        {
            if (!UnhookWindowsHookEx(hHook))
            {
                SetThreadDesktop(hCurDesk);
                CloseHandle(hCurDesk);
                OutputDebugString(L"Unhook failed..");
                break;
            }
            OutputDebugString(L"键盘钩子成功取消");
        }
        TerminateThread(hThread, 1);
        CloseHandle(hThread);

        break;
    case DLL_THREAD_ATTACH:
        break;
    case DLL_THREAD_DETACH:
        break;
    }
    return TRUE;
}

// Dll所创建线程的线程函数
DWORD WINAPI ThreadFunc()
{
    hCurDesk = GetThreadDesktop(GetCurrentThreadId());
    HDESK hUserDesk = NULL;
    // 同一桌面上进程之间只能发送窗口消息。无法跨进程与其他桌面发送它们。 
    // 同样，Windows 消息是限制应用程序定义挂钩。
    // 特定桌面中运行的进程挂钩过程将〈〈只获得针对同一桌面上创建窗口消息。〉〉
    // 所以，这里必须设置钩子所在线程的桌面为Default桌面
    // 才能使得钩子所在线程能接收到 Default 桌面的消息
    hUserDesk = OpenDesktopW(L"NewDesktop233", 0, FALSE, MAXIMUM_ALLOWED);
    SetThreadDesktop(hUserDesk);
    CloseHandle(hUserDesk);

    // 设置低级键盘钩子，屏蔽非SAS window的热键
    // 需要 #define _WIN32_WINNT 0x0500
    hHook = SetWindowsHookExW(WH_KEYBOARD_LL, KeyboardProc, GetModuleHandle(NULL), 0);
    if (hHook == NULL)
    {

        OutputDebugString(L"Set hook failed..");
        return 1;
    }
    OutputDebugString(L"键盘钩子成功设置");

    // 在非 GUI 线程中使用消息钩子必须主动接收并分发收到的消息
    MSG msg;
    while (GetMessageW(&msg, NULL, 0, 0))
    {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }

    return 1;
}


// 低级键盘钩子回调函数
LRESULT CALLBACK KeyboardProc(int nCode, WPARAM wParam, LPARAM lParam)
{
    if (nCode == HC_ACTION)
    {
        switch (wParam)
        {
        case WM_KEYDOWN:  case WM_SYSKEYDOWN:
            KBDLLHOOKSTRUCT* pKeyboardHookStruct = (KBDLLHOOKSTRUCT*)lParam;

            // 获取按键的虚拟键码
            DWORD vkCode = pKeyboardHookStruct->vkCode;

            // 检查按键是否为字母、数字或空格
            if ((vkCode >= 'A' && vkCode <= 'Z') ||
                (vkCode >= 'a' && vkCode <= 'z') ||
                (vkCode >= '0' && vkCode <= '9') ||
                vkCode == VK_SPACE)
            {
                // 允许按键
                return CallNextHookEx(NULL, nCode, wParam, lParam);
            }
            else
            {
                // 屏蔽按键
                return 1;
            }
            break;
        }
    }
    return CallNextHookEx(hHook, nCode, wParam, lParam);
}