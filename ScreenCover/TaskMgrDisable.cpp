#include <windows.h>
#include <tchar.h>
#include<Psapi.h>
#include <string>
#include <vector>
#include <cwctype>
#include<algorithm>


// �����Զ�����Ϣ
constexpr auto WM_TESTTASKMGR = 0x40B;
BOOL IsSystemWindow(HWND hwnd);

BOOL CheckAndCloseWindowUnderCursor() {
	POINT cursorPos;
	HWND hwndUnderCursor;
	DWORD windowProcessId;
	DWORD currentProcessId;
	TCHAR windowTitle[256] = { 0 };
	TCHAR className[256] = { 0 };

	// ��ȡ��ǰ���λ��
	if (!GetCursorPos(&cursorPos)) {
		//printf("��ȡ���λ��ʧ�ܣ��������: %d\n", GetLastError());
		return FALSE;
	}

	// ��ȡ���ָ���·��Ĵ���
	hwndUnderCursor = WindowFromPoint(cursorPos);
	if (!hwndUnderCursor) {
		//printf("���ָ���·�û���ҵ�����\n");
		return FALSE;
	}

	// ��ȡ������Ϣ���ڵ���
	GetWindowText(hwndUnderCursor, windowTitle, sizeof(windowTitle) / sizeof(TCHAR));
	GetClassName(hwndUnderCursor, className, sizeof(className) / sizeof(TCHAR));

	// ��ȡ���������Ľ���ID
	GetWindowThreadProcessId(hwndUnderCursor, &windowProcessId);

	// ��ȡ��ǰ����ID
	currentProcessId = GetCurrentProcessId();

	//printf("���λ��: (%d, %d)\n", cursorPos.x, cursorPos.y);
	//printf("���ھ��: 0x%p\n", hwndUnderCursor);
	//printf("���ڱ���: %s\n", windowTitle[0] ? windowTitle : "[�ޱ���]");
	//printf("��������: %s\n", className);
	//printf("���ڽ���ID: %d\n", windowProcessId);
	//printf("��ǰ����ID: %d\n", currentProcessId);

	// ����Ƿ����ڵ�ǰ����
	if (windowProcessId == currentProcessId) {
		//printf("�������ڵ�ǰ���̣������رղ���\n");
		return FALSE;
	}

	// ����Ƿ���ϵͳ�ؼ����ڣ���ѡ�İ�ȫ��飩
	if (IsSystemWindow(hwndUnderCursor)) {
		//printf("��⵽ϵͳ�ؼ����ڣ������رղ���\n");
		return FALSE;
	}

	//printf("���ڲ����ڵ�ǰ���̣����͹ر���Ϣ...\n");

	// ���͹ر���Ϣ
	if (PostMessage(hwndUnderCursor, WM_CLOSE, 0, 0)) {
		//printf("�ر���Ϣ���ͳɹ�\n");
		return TRUE;
	}
	else {
		//printf("�ر���Ϣ����ʧ�ܣ��������: %d\n", GetLastError());
		return FALSE;
	}
}

// ��������������Ƿ���ϵͳ�ؼ�����
BOOL IsSystemWindow(HWND hwnd) {
	TCHAR className[256];
	DWORD processId;
	TCHAR processName[MAX_PATH];

	// ��ȡ��������
	if (!GetClassName(hwnd, className, sizeof(className) / sizeof(TCHAR))) {
		return FALSE;
	}

	// ����Ƿ���ϵͳ�ؼ�������
	if (_tcscmp(className, TEXT("Shell_TrayWnd")) == 0 ||      // ������
		_tcscmp(className, TEXT("Progman")) == 0 ||           // ����
		_tcscmp(className, TEXT("WorkerW")) == 0 ||           // ���湤����
		_tcscmp(className, TEXT("DV2ControlHost")) == 0 ||    // ��ʼ�˵�
		_tcsstr(className, TEXT("Windows.UI")) != NULL) {     // Windows 10/11 ϵͳUI
		return TRUE;
	}

	// ��ȡ������Ϣ���н�һ�����
	GetWindowThreadProcessId(hwnd, &processId);
	HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processId);
	if (hProcess) {
		if (GetModuleFileNameEx(hProcess, NULL, processName, MAX_PATH)) {
			// ����Ƿ���ϵͳ����
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

// ��ǿ�汾��֧��ǿ�ƹر�ѡ��
BOOL CheckAndCloseWindowUnderCursorEx(BOOL forceClose, DWORD timeoutMs) {
	POINT cursorPos;
	HWND hwndUnderCursor;
	DWORD windowProcessId;
	DWORD currentProcessId;
	TCHAR windowTitle[256] = { 0 };

	// ��ȡ���λ�úʹ���
	if (!GetCursorPos(&cursorPos)) {
		return FALSE;
	}

	hwndUnderCursor = WindowFromPoint(cursorPos);
	if (!hwndUnderCursor) {
		return FALSE;
	}

	// ��ȡ������Ϣ
	GetWindowThreadProcessId(hwndUnderCursor, &windowProcessId);
	currentProcessId = GetCurrentProcessId();

	// ������ǰ���̵Ĵ���
	if (windowProcessId == currentProcessId) {
		return FALSE;
	}

	// ����ϵͳ����
	if (IsSystemWindow(hwndUnderCursor)) {
		return FALSE;
	}

	GetWindowText(hwndUnderCursor, windowTitle, sizeof(windowTitle) / sizeof(TCHAR));
	//printf("���Թرմ���: %s (PID: %d)\n",
	//    windowTitle[0] ? windowTitle : "[�ޱ���]", windowProcessId);

	// ���ȳ����Ѻùر�
	if (PostMessage(hwndUnderCursor, WM_CLOSE, 0, 0)) {
		// �ȴ����ڹر�
		DWORD startTime = GetTickCount();
		while (IsWindow(hwndUnderCursor) && (GetTickCount() - startTime) < timeoutMs) {
			Sleep(50);
		}

		// ��鴰���Ƿ��ѹر�
		if (!IsWindow(hwndUnderCursor)) {
			//printf("�����ѳɹ��ر�\n");
			return TRUE;
		}
	}

	// ����Ѻùر�ʧ��������ǿ�ƹر�
	if (forceClose && IsWindow(hwndUnderCursor)) {
		//printf("�Ѻùر�ʧ�ܣ�����ǿ�ƹر�...\n");

		// ���� WM_DESTROY
		if (PostMessage(hwndUnderCursor, WM_DESTROY, 0, 0)) {
			Sleep(100);
			if (!IsWindow(hwndUnderCursor)) {
				//      printf("������ǿ������\n");
				return TRUE;
			}
		}

		// ����ֶΣ���ֹ���̣�����ʹ�ã�
		HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, FALSE, windowProcessId);
		if (hProcess) {
			//  printf("���棺������ֹ���� %d\n", windowProcessId);
			if (TerminateProcess(hProcess, 0)) {
				// printf("��������ֹ\n");
				CloseHandle(hProcess);
				return TRUE;
			}
			CloseHandle(hProcess);
		}
	}

	//printf("�رմ���ʧ��\n");
	return FALSE;
}
BOOL CheckAndCloseActiveWindowEx(BOOL forceClose, DWORD timeoutMs) {
	//POINT cursorPos;
	HWND hwndUnderCursor;
	DWORD windowProcessId;
	DWORD currentProcessId;
	TCHAR windowTitle[256] = { 0 };

	hwndUnderCursor = GetForegroundWindow();

	// ��ȡ������Ϣ
	GetWindowThreadProcessId(hwndUnderCursor, &windowProcessId);
	currentProcessId = GetCurrentProcessId();

	// ������ǰ���̵Ĵ���
	if (windowProcessId == currentProcessId) {
		return FALSE;
	}

	// ����ϵͳ����
	if (IsSystemWindow(hwndUnderCursor)) {
		return FALSE;
	}

	GetWindowText(hwndUnderCursor, windowTitle, sizeof(windowTitle) / sizeof(TCHAR));
	//printf("���Թرմ���: %s (PID: %d)\n",
	//    windowTitle[0] ? windowTitle : "[�ޱ���]", windowProcessId);

	// ���ȳ����Ѻùر�
	if (PostMessage(hwndUnderCursor, WM_CLOSE, 0, 0)) {
		// �ȴ����ڹر�
		DWORD startTime = GetTickCount();
		while (IsWindow(hwndUnderCursor) && (GetTickCount() - startTime) < timeoutMs) {
			Sleep(50);
		}

		// ��鴰���Ƿ��ѹر�
		if (!IsWindow(hwndUnderCursor)) {
			//printf("�����ѳɹ��ر�\n");
			return TRUE;
		}
	}

	// ����Ѻùر�ʧ��������ǿ�ƹر�
	if (forceClose && IsWindow(hwndUnderCursor)) {
		//printf("�Ѻùر�ʧ�ܣ�����ǿ�ƹر�...\n");

		// ���� WM_DESTROY
		if (PostMessage(hwndUnderCursor, WM_DESTROY, 0, 0)) {
			Sleep(100);
			if (!IsWindow(hwndUnderCursor)) {
				//      printf("������ǿ������\n");
				return TRUE;
			}
		}

		// ����ֶΣ���ֹ���̣�����ʹ�ã�
		HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, FALSE, windowProcessId);
		if (hProcess) {
			//  printf("���棺������ֹ���� %d\n", windowProcessId);
			if (TerminateProcess(hProcess, 0)) {
				// printf("��������ֹ\n");
				CloseHandle(hProcess);
				return TRUE;
			}
			CloseHandle(hProcess);
		}
	}

	//printf("�رմ���ʧ��\n");
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
		// ���� DLL ����������ȥ�ظ��
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

	// ���ٷ���
	if (isFastAllowDll(fileName)) {
		return true;
	}

	// ���޷��У������� System32 ��ǩ����Ч
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
			// ������ģ�飨EXE��
			if (hMods[i] == GetModuleHandle(nullptr)) {
				continue;
			}

			bool trusted = IsMicrosoftSignedAndTrusted(modulePath);
			if (!trusted) {
				if (!isKnownDlls(modulePath)) {
					untrustedModules.push_back(modulePath);
					//FreeLibrary(hMods[i]); // ж��δǩ���������ε�ģ��

				}
				//
			// ��ѡ������ж��
			////FreeLibrary(hMods[i]);
			}
		}
	}
	if (!untrustedModules.empty()) {
		std::wstring msg = L"��⵽����δǩ���������ε�ģ�飺\n";
		for (const auto& mod : untrustedModules) {
			msg += mod + L"\n";
		}
		msg += L"��ע�ⰲȫ��";
		MessageBoxW(NULL, msg.c_str(), L"����", MB_OK | MB_ICONWARNING);
	}
	for (const auto& module : untrustedModules)
	{
		HANDLE hModule = INVALID_HANDLE_VALUE;
		try {
			const WCHAR* tmpBuf = module.data();
			hModule = GetModuleHandleW(tmpBuf);
		}
		catch (...) {
			// �����쳣������������һ��ģ��
			continue;
			//printf("ж��ģ��ʱ�����쳣��%s\n", module.c_str());
		}

		if (hModule != INVALID_HANDLE_VALUE && hModule != NULL) {
			UnmapViewOfModule(hModule);
			//CloseHandle(hModule);
		}
	}


}
*/
// ��ֹ���������������C++����
DWORD WINAPI DisableTaskMgr(LPVOID lpParam)
{
	//SetThreadDesktop((HDESK)lpParam);
	// ���������壬��ֹ�������������
	LoadLibrary(L"HotKeyHooker.dll");
	EnableMitigationPolicies();
	while (TRUE) {
		CheckAndCloseWindowUnderCursorEx(TRUE, 50); // ������λ�ò��رմ���
		CheckAndCloseActiveWindowEx(TRUE, 50); // ������ڲ��ر�
		Sleep(100);
		//CheckAndUnloadUnsignedModules(); // ��鲢ж��δǩ��ģ��
	}

	return 0;
}