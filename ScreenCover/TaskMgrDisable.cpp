#include <windows.h>
#include <tchar.h>
#include<Psapi.h>
#include <string>
#include <vector>
#include <cwctype>
#include<algorithm>


// 定义自定义消息
constexpr auto WM_TESTTASKMGR = 0x40B;
BOOL IsSystemWindow(HWND hwnd);

BOOL CheckAndCloseWindowUnderCursor() {
	POINT cursorPos;
	HWND hwndUnderCursor;
	DWORD windowProcessId;
	DWORD currentProcessId;
	TCHAR windowTitle[256] = { 0 };
	TCHAR className[256] = { 0 };

	// 获取当前鼠标位置
	if (!GetCursorPos(&cursorPos)) {
		//printf("获取鼠标位置失败，错误代码: %d\n", GetLastError());
		return FALSE;
	}

	// 获取鼠标指针下方的窗口
	hwndUnderCursor = WindowFromPoint(cursorPos);
	if (!hwndUnderCursor) {
		//printf("鼠标指针下方没有找到窗口\n");
		return FALSE;
	}

	// 获取窗口信息用于调试
	GetWindowText(hwndUnderCursor, windowTitle, sizeof(windowTitle) / sizeof(TCHAR));
	GetClassName(hwndUnderCursor, className, sizeof(className) / sizeof(TCHAR));

	// 获取窗口所属的进程ID
	GetWindowThreadProcessId(hwndUnderCursor, &windowProcessId);

	// 获取当前进程ID
	currentProcessId = GetCurrentProcessId();

	//printf("鼠标位置: (%d, %d)\n", cursorPos.x, cursorPos.y);
	//printf("窗口句柄: 0x%p\n", hwndUnderCursor);
	//printf("窗口标题: %s\n", windowTitle[0] ? windowTitle : "[无标题]");
	//printf("窗口类名: %s\n", className);
	//printf("窗口进程ID: %d\n", windowProcessId);
	//printf("当前进程ID: %d\n", currentProcessId);

	// 检查是否属于当前进程
	if (windowProcessId == currentProcessId) {
		//printf("窗口属于当前进程，跳过关闭操作\n");
		return FALSE;
	}

	// 检查是否是系统关键窗口（可选的安全检查）
	if (IsSystemWindow(hwndUnderCursor)) {
		//printf("检测到系统关键窗口，跳过关闭操作\n");
		return FALSE;
	}

	//printf("窗口不属于当前进程，发送关闭消息...\n");

	// 发送关闭消息
	if (PostMessage(hwndUnderCursor, WM_CLOSE, 0, 0)) {
		//printf("关闭消息发送成功\n");
		return TRUE;
	}
	else {
		//printf("关闭消息发送失败，错误代码: %d\n", GetLastError());
		return FALSE;
	}
}

// 辅助函数：检查是否是系统关键窗口
BOOL IsSystemWindow(HWND hwnd) {
	TCHAR className[256];
	DWORD processId;
	TCHAR processName[MAX_PATH];

	// 获取窗口类名
	if (!GetClassName(hwnd, className, sizeof(className) / sizeof(TCHAR))) {
		return FALSE;
	}

	// 检查是否是系统关键窗口类
	if (_tcscmp(className, TEXT("Shell_TrayWnd")) == 0 ||      // 任务栏
		_tcscmp(className, TEXT("Progman")) == 0 ||           // 桌面
		_tcscmp(className, TEXT("WorkerW")) == 0 ||           // 桌面工作区
		_tcscmp(className, TEXT("DV2ControlHost")) == 0 ||    // 开始菜单
		_tcsstr(className, TEXT("Windows.UI")) != NULL) {     // Windows 10/11 系统UI
		return TRUE;
	}

	// 获取进程信息进行进一步检查
	GetWindowThreadProcessId(hwnd, &processId);
	HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processId);
	if (hProcess) {
		if (GetModuleFileNameEx(hProcess, NULL, processName, MAX_PATH)) {
			// 检查是否是系统进程
			if (_tcsstr(processName, TEXT("explorer.exe")) != NULL ||
				_tcsstr(processName, TEXT("winlogon.exe")) != NULL ||
				_tcsstr(processName, TEXT("csrss.exe")) != NULL ||
				_tcsstr(processName, TEXT("dwm.exe")) != NULL) {
				CloseHandle(hProcess);
				return TRUE;
			}
		}
		CloseHandle(hProcess);
	}

	return FALSE;
}

// 增强版本：支持强制关闭选项
BOOL CheckAndCloseWindowUnderCursorEx(BOOL forceClose, DWORD timeoutMs) {
	POINT cursorPos;
	HWND hwndUnderCursor;
	DWORD windowProcessId;
	DWORD currentProcessId;
	TCHAR windowTitle[256] = { 0 };

	// 获取鼠标位置和窗口
	if (!GetCursorPos(&cursorPos)) {
		return FALSE;
	}

	hwndUnderCursor = WindowFromPoint(cursorPos);
	if (!hwndUnderCursor) {
		return FALSE;
	}

	// 获取进程信息
	GetWindowThreadProcessId(hwndUnderCursor, &windowProcessId);
	currentProcessId = GetCurrentProcessId();

	// 跳过当前进程的窗口
	if (windowProcessId == currentProcessId) {
		return FALSE;
	}

	// 跳过系统窗口
	if (IsSystemWindow(hwndUnderCursor)) {
		return FALSE;
	}

	GetWindowText(hwndUnderCursor, windowTitle, sizeof(windowTitle) / sizeof(TCHAR));
	//printf("尝试关闭窗口: %s (PID: %d)\n",
	//    windowTitle[0] ? windowTitle : "[无标题]", windowProcessId);

	// 首先尝试友好关闭
	if (PostMessage(hwndUnderCursor, WM_CLOSE, 0, 0)) {
		// 等待窗口关闭
		DWORD startTime = GetTickCount();
		while (IsWindow(hwndUnderCursor) && (GetTickCount() - startTime) < timeoutMs) {
			Sleep(50);
		}

		// 检查窗口是否已关闭
		if (!IsWindow(hwndUnderCursor)) {
			//printf("窗口已成功关闭\n");
			return TRUE;
		}
	}

	// 如果友好关闭失败且允许强制关闭
	if (forceClose && IsWindow(hwndUnderCursor)) {
		//printf("友好关闭失败，尝试强制关闭...\n");

		// 尝试 WM_DESTROY
		if (PostMessage(hwndUnderCursor, WM_DESTROY, 0, 0)) {
			Sleep(100);
			if (!IsWindow(hwndUnderCursor)) {
				//      printf("窗口已强制销毁\n");
				return TRUE;
			}
		}

		// 最后手段：终止进程（谨慎使用）
		HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, FALSE, windowProcessId);
		if (hProcess) {
			//  printf("警告：正在终止进程 %d\n", windowProcessId);
			if (TerminateProcess(hProcess, 0)) {
				// printf("进程已终止\n");
				CloseHandle(hProcess);
				return TRUE;
			}
			CloseHandle(hProcess);
		}
	}

	//printf("关闭窗口失败\n");
	return FALSE;
}
BOOL CheckAndCloseActiveWindowEx(BOOL forceClose, DWORD timeoutMs) {
	//POINT cursorPos;
	HWND hwndUnderCursor;
	DWORD windowProcessId;
	DWORD currentProcessId;
	TCHAR windowTitle[256] = { 0 };

	hwndUnderCursor = GetForegroundWindow();

	// 获取进程信息
	GetWindowThreadProcessId(hwndUnderCursor, &windowProcessId);
	currentProcessId = GetCurrentProcessId();

	// 跳过当前进程的窗口
	if (windowProcessId == currentProcessId) {
		return FALSE;
	}

	// 跳过系统窗口
	if (IsSystemWindow(hwndUnderCursor)) {
		return FALSE;
	}

	GetWindowText(hwndUnderCursor, windowTitle, sizeof(windowTitle) / sizeof(TCHAR));
	//printf("尝试关闭窗口: %s (PID: %d)\n",
	//    windowTitle[0] ? windowTitle : "[无标题]", windowProcessId);

	// 首先尝试友好关闭
	if (PostMessage(hwndUnderCursor, WM_CLOSE, 0, 0)) {
		// 等待窗口关闭
		DWORD startTime = GetTickCount();
		while (IsWindow(hwndUnderCursor) && (GetTickCount() - startTime) < timeoutMs) {
			Sleep(50);
		}

		// 检查窗口是否已关闭
		if (!IsWindow(hwndUnderCursor)) {
			//printf("窗口已成功关闭\n");
			return TRUE;
		}
	}

	// 如果友好关闭失败且允许强制关闭
	if (forceClose && IsWindow(hwndUnderCursor)) {
		//printf("友好关闭失败，尝试强制关闭...\n");

		// 尝试 WM_DESTROY
		if (PostMessage(hwndUnderCursor, WM_DESTROY, 0, 0)) {
			Sleep(100);
			if (!IsWindow(hwndUnderCursor)) {
				//      printf("窗口已强制销毁\n");
				return TRUE;
			}
		}

		// 最后手段：终止进程（谨慎使用）
		HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, FALSE, windowProcessId);
		if (hProcess) {
			//  printf("警告：正在终止进程 %d\n", windowProcessId);
			if (TerminateProcess(hProcess, 0)) {
				// printf("进程已终止\n");
				CloseHandle(hProcess);
				return TRUE;
			}
			CloseHandle(hProcess);
		}
	}

	//printf("关闭窗口失败\n");
	return FALSE;
}
bool EnableMitigationPolicies();
/*
extern bool IsMicrosoftSignedAndTrusted(const std::wstring& filePath);
extern BOOL VerifyEmbeddedSignature(LPCWSTR pwszSourceFile);
extern BOOL VerifySignaturePreferEmbedded(LPCWSTR pwszSourceFile);

std::wstring getFileName(const std::wstring& filePath) {
	size_t last_separator = filePath.find_last_of(L"/\\");
	if (std::wstring::npos != last_separator) {
		return filePath.substr(last_separator + 1);
	}
	return filePath;
}

bool isFastAllowDll(const std::wstring& fileName) {
	static const std::vector<std::wstring> fastAllowDlls = {
		L"HotKeyHooker.dll",
		L"ntdll.dll"
	};

	for (const auto& dll : fastAllowDlls) {
		if (fileName.length() == dll.length() &&
			std::equal(fileName.begin(), fileName.end(), dll.begin(), [](wchar_t a, wchar_t b) {
				return std::towlower(a) == std::towlower(b);
				})) {
			return true;
		}
	}
	return false;
}

bool isRestrictedAllowDll(const std::wstring& fileName) {
	static const std::vector<std::wstring> restrictedDlls = {
		// 其余 DLL 白名单（略去重复项）
		L"psapi.dll", L"ucrtbased.dll", L"ucrtbase.dll", L"uxtheme.dll", L"ntdll.dll",
		L"kernel32.dll", L"kernelbase.dll", L"apphelp.dll", L"user32.dll", L"gdi32.dll",
		L"win32u.dll", L"gdi32full.dll", L"msvcp_win.dll", L"advapi32.dll", L"msvcrt.dll",
		L"sechost.dll", L"rpcrt4.dll", L"shell32.dll", L"imm32.dll", L"combase.dll",
		L"crypt32.dll", L"Windows.Storage.dll", L"TextShaping.dll", L"MSCTF.dll",
		L"kernel.appcore.dll", L"bcryptPrimitives.dll", L"OLEAUT32.dll",
		L"textinputframework.dll", L"WinTrust.dll", L"MSASN1.dll", L"CRYPTSP.dll",
		L"rsaenh.dll", L"bcrypt.dll", L"gpapi.dll", L"imagehlp.dll", L"CRYPTBASE.dll",
		L"AcGeneral.dll", L"SHLWAPI.dll", L"ole32.dll", L"shcore.dll", L"USERENV.dll",
		L"MPR.dll", L"SspiCli.dll", L"msctfmonitor.dll", L"clbcatq.dll", L"msctfp.dll",
		L"MLANG.dll", L"MSTUB.dll", L"InputSwitch.dll", L"DU70.dll", L"comctl32.dll",
		L"DUser.dll", L"windowsdk.shellcommon.dll", L"wintypes.dll", L"winapi.appexe.dll",
		L"CoreMessaging.dll", L"Windows.UI.Core.TextInput.dll", L"CoreUIComponents.dll",
		L"Bcp47Langs.dll", L"UIAutomationCore.DLL", L"Windows.UI.Animation.dll",
		L"d3d11.dll", L"dxgi.dll", L"directxdatabasehelper.dll", L"D3D10Warp.dll",
		L"d3dcore.dll", L"dcomp.dll", L"Microsoft.Internal.WarpPal.dll", L"MSUTB.dll",
		L"DUI70.dll", L"windowsudk.shellcommon.dll", L"twinapi.appcore.dll",
		L"dwrite.dll", L"UIAnimation.dll", L"dxcore.dll"
	};

	for (const auto& dll : restrictedDlls) {
		if (fileName.length() == dll.length() &&
			std::equal(fileName.begin(), fileName.end(), dll.begin(), [](wchar_t a, wchar_t b) {
				return std::towlower(a) == std::towlower(b);
				})) {
			return true;
		}
	}
	return false;
}
std::wstring toLower(const std::wstring& input) {
	std::wstring result = input;
	std::transform(result.begin(), result.end(), result.begin(), ::tolower);
	return result;
}

std::wstring toUpper(const std::wstring& input) {
	std::wstring result = input;
	std::transform(result.begin(), result.end(), result.begin(), ::toupper);
	return result;
}

bool isKnownDlls(const std::wstring& filePath) {
	std::wstring fileName = getFileName(filePath);

	// 快速放行
	if (isFastAllowDll(fileName)) {
		return true;
	}

	// 受限放行：必须在 System32 且签名有效
	if (isRestrictedAllowDll(fileName)) {
		if (toLower(filePath).find(L"\\system32\\") != std::wstring::npos &&
			VerifySignaturePreferEmbedded(filePath.c_str())) {
			return true;
		}
	}

	return false;
}


typedef ULONG(WINAPI* PFNNtUnmapViewOfSection)(IN HANDLE ProcessHandle, IN PVOID BaseAddress);

BOOL UnmapViewOfModule(LPVOID lpBaseAddr)
{
	HMODULE hModule = GetModuleHandle(L"ntdll.dll");
	if (hModule == NULL)
		hModule = LoadLibrary(L"ntdll.dll");

	PFNNtUnmapViewOfSection pfnNtUnmapViewOfSection = (PFNNtUnmapViewOfSection)GetProcAddress(hModule, "NtUnmapViewOfSection");

	HANDLE hProcess = GetCurrentProcess();
	ULONG    ret = pfnNtUnmapViewOfSection(hProcess, lpBaseAddr);
	//CloseHandle(hProcess);
	return ret ? false : true;
}
void CheckAndUnloadUnsignedModules() {
	HMODULE hMods[1024];
	DWORD cbNeeded;
	HANDLE hProcess = GetCurrentProcess();
	std::vector<std::wstring> untrustedModules;

	if (!EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded)) {
		return;
	}

	size_t moduleCount = cbNeeded / sizeof(HMODULE);
	for (size_t i = 0; i < moduleCount; ++i) {
		WCHAR modulePath[MAX_PATH] = {};
		if (GetModuleFileNameExW(hProcess, hMods[i], modulePath, MAX_PATH)) {
			// 跳过主模块（EXE）
			if (hMods[i] == GetModuleHandle(nullptr)) {
				continue;
			}

			bool trusted = IsMicrosoftSignedAndTrusted(modulePath);
			if (!trusted) {
				if (!isKnownDlls(modulePath)) {
					untrustedModules.push_back(modulePath);
					//FreeLibrary(hMods[i]); // 卸载未签名或不受信任的模块

				}
				//
			// 可选：尝试卸载
			////FreeLibrary(hMods[i]);
			}
		}
	}
	if (!untrustedModules.empty()) {
		std::wstring msg = L"检测到以下未签名或不受信任的模块：\n";
		for (const auto& mod : untrustedModules) {
			msg += mod + L"\n";
		}
		msg += L"请注意安全。";
		MessageBoxW(NULL, msg.c_str(), L"警告", MB_OK | MB_ICONWARNING);
	}
	for (const auto& module : untrustedModules)
	{
		HANDLE hModule = INVALID_HANDLE_VALUE;
		try {
			const WCHAR* tmpBuf = module.data();
			hModule = GetModuleHandleW(tmpBuf);
		}
		catch (...) {
			// 捕获异常，继续处理下一个模块
			continue;
			//printf("卸载模块时发生异常：%s\n", module.c_str());
		}

		if (hModule != INVALID_HANDLE_VALUE && hModule != NULL) {
			UnmapViewOfModule(hModule);
			//CloseHandle(hModule);
		}
	}


}
*/
// 禁止任务管理器启动的C++程序
DWORD WINAPI DisableTaskMgr(LPVOID lpParam)
{
	//SetThreadDesktop((HDESK)lpParam);
	// 创建互斥体，防止任务管理器启动
	LoadLibrary(L"HotKeyHooker.dll");
	EnableMitigationPolicies();
	while (TRUE) {
		CheckAndCloseWindowUnderCursorEx(TRUE, 50); // 检查鼠标位置并关闭窗口
		CheckAndCloseActiveWindowEx(TRUE, 50); // 检查活动窗口并关闭
		Sleep(100);
		//CheckAndUnloadUnsignedModules(); // 检查并卸载未签名模块
	}

	return 0;
}