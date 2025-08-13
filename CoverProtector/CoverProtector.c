#include<Ntifs.h>
#include <ntstrsafe.h>
//#include <winnt.h>



#define PROCESS_TERMINATE                  (0x0001)  
#define PROCESS_CREATE_THREAD              (0x0002)  
#define PROCESS_SET_SESSIONID              (0x0004)  
#define PROCESS_VM_OPERATION               (0x0008)  
#define PROCESS_VM_READ                    (0x0010)  
#define PROCESS_VM_WRITE                   (0x0020)  
#define PROCESS_DUP_HANDLE                 (0x0040)  
#define PROCESS_CREATE_PROCESS             (0x0080)  
#define PROCESS_SET_QUOTA                  (0x0100)  
#define PROCESS_SET_INFORMATION            (0x0200)  
#define PROCESS_QUERY_INFORMATION          (0x0400)  
#define PROCESS_SUSPEND_RESUME             (0x0800)  
#define PROCESS_QUERY_LIMITED_INFORMATION  (0x1000)  
#define PROCESS_SET_LIMITED_INFORMATION    (0x2000)  

// ��������
NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath);
VOID DriverUnload(PDRIVER_OBJECT DriverObject);
OB_PREOP_CALLBACK_STATUS ObjectPreCallback(PVOID RegistrationContext, POB_PRE_OPERATION_INFORMATION OperationInformation);
//NTSTATUS PsSetLoadImageNotifyRoutine(PLOAD_IMAGE_NOTIFY_ROUTINE NotifyRoutine);
VOID ImageLoadCallback(PUNICODE_STRING FullImageName, HANDLE ProcessId, PIMAGE_INFO ImageInfo);
BOOLEAN IsProcessScreenCover(HANDLE ProcessId);
BOOLEAN IsProcessCsrss(HANDLE ProcessId);
BOOLEAN IsProcessSvchost(HANDLE ProcessId);
BOOLEAN IsProcessDesktopInitial(HANDLE ProcessId);
BOOLEAN IsProcessMsMpEng(HANDLE ProcessId);
BOOLEAN IsProcessIME(HANDLE ProcessId);
BOOLEAN IsMicrosoftSigned(PIMAGE_INFO ImageInfo);
BOOLEAN IsAllowedModule(PUNICODE_STRING FullImageName);

// ȫ�ֱ���
PVOID g_ObjectCallbackHandle = NULL;
PVOID g_ProcessCallbackHandle = NULL;

// ����������ڵ�
NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
    UNREFERENCED_PARAMETER(RegistryPath);

    NTSTATUS status = STATUS_SUCCESS;
    OB_OPERATION_REGISTRATION operationRegistrations[2];
    OB_CALLBACK_REGISTRATION callbackRegistration;

    DriverObject->DriverUnload = DriverUnload;

    // ���ö���ص�ע��
    RtlZeroMemory(&operationRegistrations, sizeof(operationRegistrations));

    // �������ص�
    operationRegistrations[0].ObjectType = ExDesktopObjectType;
    operationRegistrations[0].Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
    operationRegistrations[0].PreOperation = ObjectPreCallback;
    operationRegistrations[0].PostOperation = NULL;

    // ���̶���ص�
    operationRegistrations[1].ObjectType = PsProcessType;
    operationRegistrations[1].Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
    operationRegistrations[1].PreOperation = ObjectPreCallback;
    operationRegistrations[1].PostOperation = NULL;

    // ע�����ص�
    RtlZeroMemory(&callbackRegistration, sizeof(callbackRegistration));
    callbackRegistration.Version = OB_FLT_REGISTRATION_VERSION;
    callbackRegistration.OperationRegistrationCount = 2;
    callbackRegistration.OperationRegistration = operationRegistrations;
    callbackRegistration.RegistrationContext = NULL;

    status = ObRegisterCallbacks(&callbackRegistration, &g_ObjectCallbackHandle);
    if (!NT_SUCCESS(status)) {
        KdPrint(("Failed to register object callbacks: 0x%X\n", status));
        return status;
    }

    // ע�᾵����ػص�
    status = PsSetLoadImageNotifyRoutine(ImageLoadCallback);
    if (!NT_SUCCESS(status)) {
        KdPrint(("Failed to register image load callback: 0x%X\n", status));
        if (g_ObjectCallbackHandle) {
            ObUnRegisterCallbacks(g_ObjectCallbackHandle);
            g_ObjectCallbackHandle = NULL;
        }
        return status;
    }

    KdPrint(("Major Privacy Security Driver loaded successfully\n"));
    return STATUS_SUCCESS;
}

// ��������ж��
VOID DriverUnload(PDRIVER_OBJECT DriverObject)
{
    UNREFERENCED_PARAMETER(DriverObject);

    if (g_ObjectCallbackHandle) {
        ObUnRegisterCallbacks(g_ObjectCallbackHandle);
        g_ObjectCallbackHandle = NULL;
    }

    PsRemoveLoadImageNotifyRoutine(ImageLoadCallback);

    KdPrint(("Major Privacy Security Driver unloaded\n"));
}

// ��������ص�
OB_PREOP_CALLBACK_STATUS ObjectPreCallback(PVOID RegistrationContext, POB_PRE_OPERATION_INFORMATION OperationInformation)
{
    UNREFERENCED_PARAMETER(RegistrationContext);

    HANDLE currentProcessId = PsGetCurrentProcessId();
    PEPROCESS currentProcess = PsGetCurrentProcess();
	UNREFERENCED_PARAMETER(currentProcess);
    POBJECT_NAME_INFORMATION objectNameInfo = NULL;
    ULONG returnLength;
    NTSTATUS status;

    // ����Ƿ����������
    if (OperationInformation->ObjectType == *ExDesktopObjectType) {
        // ��һ�ε��ã���ȡ���賤��
        status = ObQueryNameString(OperationInformation->Object, NULL, 0, &returnLength);
        // KdPrint(("ObQueryNameString initial status: 0x%X, returnLength: %lu\n", status, returnLength));

        if (status == STATUS_INFO_LENGTH_MISMATCH && returnLength > 0) {
            objectNameInfo = (POBJECT_NAME_INFORMATION)ExAllocatePool2(
                POOL_FLAG_NON_PAGED,
                returnLength,
                'tksD'
            );

            if (objectNameInfo) {
                status = ObQueryNameString(OperationInformation->Object, objectNameInfo, returnLength, &returnLength);
                // KdPrint(("ObQueryNameString second status: 0x%X\n", status));

                if (NT_SUCCESS(status) && objectNameInfo->Name.Buffer) {
                    __try {
                         //KdPrint(("Checking desktop: %wZ\n", &objectNameInfo->Name));

                        // ����Ƿ���Ŀ������
                        WCHAR* nameTail = wcsrchr(objectNameInfo->Name.Buffer, L'\\');
                        if (nameTail && _wcsicmp(nameTail + 1, L"NewDesktop233") == 0) {

                            if (!IsProcessCsrss(currentProcessId) &&
                                !IsProcessScreenCover(currentProcessId) &&
                                !HandleToULong(currentProcessId) == 4/* &&
                                !IsProcessIME(currentProcessId)*/) {
                            if (OperationInformation->Operation == OB_OPERATION_HANDLE_CREATE) {
                                KdPrint(("Blocked access to NewDesktop233 from process %lu\n", HandleToULong(currentProcessId)));
                                KdPrint(("Blocked access to NewDesktop233"));
                                OperationInformation->Parameters->CreateHandleInformation.DesiredAccess &= ~(GENERIC_READ | GENERIC_WRITE | GENERIC_EXECUTE);
                                ExFreePoolWithTag(objectNameInfo, 'tksD');
                                return OB_PREOP_SUCCESS;
                            }
                            else if (OperationInformation->Operation == OB_OPERATION_HANDLE_DUPLICATE) {
                                KdPrint(("Blocked handle duplication to NewDesktop233 from process %lu\n", HandleToULong(currentProcessId)));
                                KdPrint(("Blocked access to NewDesktop233"));
                                OperationInformation->Parameters->DuplicateHandleInformation.DesiredAccess &= ~(GENERIC_READ | GENERIC_WRITE | GENERIC_EXECUTE);
                                ExFreePoolWithTag(objectNameInfo, 'tksD');
                                return OB_PREOP_SUCCESS;
                            }
                            }
                        }
                    }
                    __except (EXCEPTION_EXECUTE_HANDLER) {
                        KdPrint(("Exception occurred while parsing desktop name\n"));
                    }
                }
                else {
                    KdPrint(("ObQueryNameString failed or Name.Buffer is NULL\n"));
                }

                // ʼ���ͷ��ڴ棬����й©������ָ��
                ExFreePoolWithTag(objectNameInfo, 'tksD');
            }
            else {
                KdPrint(("Failed to allocate memory for objectNameInfo\n"));
            }
        }
        else {
            KdPrint(("ObQueryNameString did not return STATUS_INFO_LENGTH_MISMATCH\n"));
        }
    }

    // ����Ƿ��ǽ��̶���
    else if (OperationInformation->ObjectType == *PsProcessType) {
        PEPROCESS targetProcess = (PEPROCESS)OperationInformation->Object;
        HANDLE targetProcessId = PsGetProcessId(targetProcess);

        // ���Ŀ������Ƿ���ScreenCover.exe
        if (IsProcessScreenCover(targetProcessId)) {
            // �������ķ���Ȩ���Ƿ����дȨ��
            if (OperationInformation->Parameters->CreateHandleInformation.OriginalDesiredAccess &
                (PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_CREATE_THREAD |
                    PROCESS_SET_INFORMATION | PROCESS_SUSPEND_RESUME | PROCESS_TERMINATE)) {
                if (IsProcessCsrss(currentProcessId)) {
                    OperationInformation->Parameters->CreateHandleInformation.DesiredAccess &=
                        ~(PROCESS_TERMINATE);
                }
                // ֻ����Csrss.exe��ScreenCover.exe��svchost.exe��DesktopInitial.exe��MsMpEng.exe������дȨ�޷���
                if (!IsProcessCsrss(currentProcessId) && !IsProcessScreenCover(currentProcessId)
                    && !IsProcessSvchost(currentProcessId) && !IsProcessDesktopInitial(currentProcessId)
                    && !IsProcessMsMpEng(currentProcessId) && (HandleToULong(currentProcessId) != 4)) {
                    KdPrint(("Blocked write access to ScreenCover.exe from process %lu\n", HandleToULong(currentProcessId)));
                    OperationInformation->Parameters->CreateHandleInformation.DesiredAccess &=
                        ~(PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_CREATE_THREAD |
                            PROCESS_SET_INFORMATION | PROCESS_SUSPEND_RESUME | PROCESS_TERMINATE);
                }
            }
        }
    }

    return OB_PREOP_SUCCESS;
}
// ���� MmUnmapViewOfSection ������ж���Ѿ����ص� DLL ģ��
NTSTATUS DenyLoadDll(HANDLE ProcessId, PVOID pImageBase)
{
    NTSTATUS status = STATUS_SUCCESS;
    PEPROCESS pEProcess = NULL;

    status = PsLookupProcessByProcessId(ProcessId, &pEProcess);
    if (!NT_SUCCESS(status))
    {
        return status;
    }

    // ж��ģ��
    status = ZwUnmapViewOfSection(pEProcess, pImageBase);
    if (!NT_SUCCESS(status))
    {
        return status;
    }
    return status;
}

// ������ػص�
VOID ImageLoadCallback(PUNICODE_STRING FullImageName, HANDLE ProcessId, PIMAGE_INFO ImageInfo)
{
    // ����Ƿ���ScreenCover.exe���̼���ģ��
    if (!ImageInfo)
        return;
    if (ProcessId == 0||ImageInfo->SystemModeImage==1)
        return;
    if (!IsProcessScreenCover(ProcessId)) {
        return;
    }
	//KdPrint(("ImageLoadCallback called for process %lu, image: %wZ\n", HandleToULong(ProcessId), FullImageName));
    // ����������ģ�飬ֱ�ӷ���
    if (IsAllowedModule(FullImageName)) {
        return;
    }
	//KdPrint(("Checking module: %wZ in ScreenCover.exe\n", FullImageName));
    // ����Ƿ���΢��ǩ����ģ��
    if (!IsMicrosoftSigned(ImageInfo)) {
       // KdPrint(("Blocked non-Microsoft signed module load in ScreenCover.exe: %wZ\n", FullImageName));
        // ע�⣺ʵ����ֹ������Ҫ��PreCallback��ʵ�֣�����ֻ�Ǽ�¼
        // ��ʵ��ʵ���У���������Ҫʹ��������������ֹģ�����
        if (ImageInfo && ImageInfo->ImageBase) {
            DenyLoadDll(ProcessId, ImageInfo->ImageBase);
			KdPrint(("Unloaded module: %wZ from ScreenCover.exe\n", FullImageName));
        }
    }
}

// �������Ƿ���ScreenCover.exe
BOOLEAN IsProcessScreenCover(HANDLE ProcessId)
{
    PEPROCESS process;
    NTSTATUS status = PsLookupProcessByProcessId(ProcessId, &process);

    if (NT_SUCCESS(status)) {
        PUNICODE_STRING processImageName = NULL;
        status = SeLocateProcessImageName(process, &processImageName);

        if (NT_SUCCESS(status) && processImageName && processImageName->Buffer) {
            WCHAR* fileName = wcsrchr(processImageName->Buffer, L'\\');
            if (fileName) {
                fileName++; // ������б��
                if (_wcsicmp(fileName, L"ScreenCover.exe") == 0) {
                    ExFreePool(processImageName);
                    ObDereferenceObject(process);
                    return TRUE;
                }
            }
            ExFreePool(processImageName);
        }
        ObDereferenceObject(process);
    }

    return FALSE;
}

// �������Ƿ���Csrss.exe
BOOLEAN IsProcessCsrss(HANDLE ProcessId)
{
    PEPROCESS process;
    NTSTATUS status = PsLookupProcessByProcessId(ProcessId, &process);

    if (NT_SUCCESS(status)) {
        PUNICODE_STRING processImageName = NULL;
        status = SeLocateProcessImageName(process, &processImageName);

        if (NT_SUCCESS(status) && processImageName && processImageName->Buffer) {
            WCHAR* fileName = wcsrchr(processImageName->Buffer, L'\\');
            if (fileName) {
                fileName++; // ������б��
                if (_wcsicmp(fileName, L"csrss.exe") == 0) {
                    ExFreePool(processImageName);
                    ObDereferenceObject(process);
                    return TRUE;
                }
            }
            ExFreePool(processImageName);
        }
        ObDereferenceObject(process);
    }

    return FALSE;
}
//ChsIME.exe
BOOLEAN IsProcessIME(HANDLE ProcessId)
{
    PEPROCESS process;
    NTSTATUS status = PsLookupProcessByProcessId(ProcessId, &process);
    if (NT_SUCCESS(status)) {
        PUNICODE_STRING processImageName = NULL;
        status = SeLocateProcessImageName(process, &processImageName);
        if (NT_SUCCESS(status) && processImageName && processImageName->Buffer) {
            WCHAR* fileName = wcsrchr(processImageName->Buffer, L'\\');
            if (fileName) {
                fileName++; // ������б��
                if (_wcsicmp(fileName, L"ChsIME.exe") == 0) {
                    ExFreePool(processImageName);
                    ObDereferenceObject(process);
                    return TRUE;
                }
            }
            ExFreePool(processImageName);
        }
        ObDereferenceObject(process);
    }
    return FALSE;
}
// �������Ƿ���svchost.exe
BOOLEAN IsProcessSvchost(HANDLE ProcessId)
{
    PEPROCESS process;
    NTSTATUS status = PsLookupProcessByProcessId(ProcessId, &process);

    if (NT_SUCCESS(status)) {
        PUNICODE_STRING processImageName = NULL;
        status = SeLocateProcessImageName(process, &processImageName);

        if (NT_SUCCESS(status) && processImageName && processImageName->Buffer) {
            WCHAR* fileName = wcsrchr(processImageName->Buffer, L'\\');
            if (fileName) {
                fileName++;
                if (_wcsicmp(fileName, L"svchost.exe") == 0) {
                    ExFreePool(processImageName);
                    ObDereferenceObject(process);
                    return TRUE;
                }
            }
            ExFreePool(processImageName);
        }
        ObDereferenceObject(process);
    }

    return FALSE;
}

// �������Ƿ���DesktopInitial.exe
BOOLEAN IsProcessDesktopInitial(HANDLE ProcessId)
{
    PEPROCESS process;
    NTSTATUS status = PsLookupProcessByProcessId(ProcessId, &process);

    if (NT_SUCCESS(status)) {
        PUNICODE_STRING processImageName = NULL;
        status = SeLocateProcessImageName(process, &processImageName);

        if (NT_SUCCESS(status) && processImageName && processImageName->Buffer) {
            WCHAR* fileName = wcsrchr(processImageName->Buffer, L'\\');
            if (fileName) {
                fileName++;
                if (_wcsicmp(fileName, L"DesktopInitial.exe") == 0) {
                    ExFreePool(processImageName);
                    ObDereferenceObject(process);
                    return TRUE;
                }
            }
            ExFreePool(processImageName);
        }
        ObDereferenceObject(process);
    }

    return FALSE;
}

// �������Ƿ���MsMpEng.exe
BOOLEAN IsProcessMsMpEng(HANDLE ProcessId)
{
    PEPROCESS process;
    NTSTATUS status = PsLookupProcessByProcessId(ProcessId, &process);

    if (NT_SUCCESS(status)) {
        PUNICODE_STRING processImageName = NULL;
        status = SeLocateProcessImageName(process, &processImageName);

        if (NT_SUCCESS(status) && processImageName && processImageName->Buffer) {
            WCHAR* fileName = wcsrchr(processImageName->Buffer, L'\\');
            if (fileName) {
                fileName++;
                if (_wcsicmp(fileName, L"MsMpEng.exe") == 0) {
                    ExFreePool(processImageName);
                    ObDereferenceObject(process);
                    return TRUE;
                }
            }
            ExFreePool(processImageName);
        }
        ObDereferenceObject(process);
    }

    return FALSE;
}

// ���ģ���Ƿ��������ģ��
BOOLEAN IsAllowedModule(PUNICODE_STRING FullImageName)
{
    if (!FullImageName || !FullImageName->Buffer) {
        return FALSE;
    }

    WCHAR* fileName = wcsrchr(FullImageName->Buffer, L'\\');
    if (fileName) {
        fileName++; // ������б��

        // ����ScreenCover.exe�������HotKeyHooker.dll
        if (_wcsicmp(fileName, L"ScreenCover.exe") == 0 ||
            _wcsicmp(fileName, L"HotKeyHooker.dll") == 0 ||
            _wcsicmp(fileName, L"ntdll.dll") == 0) {
            return TRUE;
        }

    }

    return FALSE;
}

// ���ģ���Ƿ���΢��ǩ��
BOOLEAN IsMicrosoftSigned(PIMAGE_INFO ImageInfo)
{
    // ����һ���򻯵�ʵ��
    // ��ʵ��ʵ���У�����Ҫ��֤����ǩ��
    // �������ϵͳģ��·���µ��ļ�����΢��ǩ����

    if (ImageInfo && ImageInfo->ImageSignatureLevel>=SE_SIGNING_LEVEL_MICROSOFT) {
        return TRUE;
    }

    // ������Ӹ����ӵ�ǩ����֤�߼�
    // ������֤��������֤ǩ����

    return FALSE;
}