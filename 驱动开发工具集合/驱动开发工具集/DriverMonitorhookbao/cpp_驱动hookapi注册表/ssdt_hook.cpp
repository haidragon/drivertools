/*��� SSDT ���� Ŀ¼ ע��� ���� ���£�
http://hi.baidu.com/_wang8/blog/item/bc6b23063b40cd7e0308815b.html
>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
|ע���������ת�أ��뱣��������Ϣ��лл
|���³�����http://hi.baidu.com/_wang8
|>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
/*
XLMonitor.c (XLMonitor.sys)
create 
modify 
//
HOOK SSDT�������º���
ϵͳ���̼�أ�
ZwCreateProcessEx
ZwTerminateProcess
�ļ�Ŀ¼��أ�
NtCreateFile
NtOpenFile
NtWriteFile
NtDeleteFile
ע����أ�
NtSetValueKey
NtDeleteKey
NtCreateKey
NtDeleteValueKey
�������ؼ�أ�
ZwLoadDriver 
*/
#pragma comment(lib,"Dbghelp.lib")
// *******************ͷ�ļ�********************************************

#include "driver.h"
//#include <wdm.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
//#include <ntddk.h>
#include <ntimage.h>

//#include "dbghelp.h"
#include "XLMonitor.h"
//#ifndef CALLBACK
//#define CALLBACK __stdcall
//#endif

#define DWORD unsigned long
#define WORD unsigned short
#define BOOL unsigned long
#define BYTE unsigned char

//#include <imagehlp.h>
//////////////////////////////////////////////////////////////////////////
#define MAXPATHLEN 256
#define SEC_IMAGE    0x01000000
//������ַ
int    position;//ZwCreateProcess
int    pos; //
int    po;
int    ps;//NtOpenProcess
int    pts;//ZwTerminateProcess
int    inxNtSetValueKey;
int    inxNtDeleteValueKey;
int    inxNtDeleteKey;
int    inxNtCreateKey;
int    inxNtCreateFile;
int    inxNtOpenFile;
int    inxNtWriteFile;
int    inxNtDeleteFile;
//����

NTSTATUS 
DevCreateClose
(
IN PDEVICE_OBJECT DeviceObject,
IN PIRP Irp
);
NTSTATUS 
DevDispatch
(
IN PDEVICE_OBJECT DeviceObject,
IN PIRP Irp
);
NTSTATUS PsLookupProcessByProcessId
(
IN ULONG ulProcId, 
OUT PEPROCESS * pEProcess
);
//ϵͳ�����SSDT �ṹ����
typedef struct ServiceDescriptorEntry {
unsigned int *ServiceTableBase;//ָ��ϵͳ��������ַ��
unsigned int *ServiceCounterTableBase; //Used only in checked build�ؼ�
unsigned int NumberOfServices; //�������ĸ���,NumberOfService*4 ����������ַ��Ĵ�С
unsigned char *ParamTableBase;
} ServiceDescriptorTableEntry, *PServiceDescriptorTableEntry;
// KeServiceDescriptorTableΪntoskrnl.exe����
//extern PSRVTABLE KeServiceDescriptorTable;
extern "C"{
extern PServiceDescriptorTableEntry KeServiceDescriptorTable; 
}
//typedef struct _FILE_NAME_INFORMATION {
// ULONG FileNameLength;
// WCHAR FileName[1];
//} FILE_NAME_INFORMATION, *PFILE_NAME_INFORMATION;
//�ļ�/Ŀ¼��������
typedef NTSTATUS (*NTCREATEFILE)
(
OUT PHANDLE FileHandle,
IN ACCESS_MASK DesiredAccess,
IN POBJECT_ATTRIBUTES ObjectAttributes,
OUT PIO_STATUS_BLOCK IoStatusBlock,
IN PLARGE_INTEGER AllocationSize OPTIONAL,
IN ULONG FileAttributes,
IN ULONG ShareAccess,
IN ULONG CreateDisposition,
IN ULONG CreateOptions,
IN PVOID EaBuffer OPTIONAL,
IN ULONG EaLength
);
NTSTATUS FakedNtCreateFile
(
OUT PHANDLE FileHandle,
IN ACCESS_MASK DesiredAccess,
IN POBJECT_ATTRIBUTES ObjectAttributes,
OUT PIO_STATUS_BLOCK IoStatusBlock,
IN PLARGE_INTEGER AllocationSize OPTIONAL,
IN ULONG FileAttributes,
IN ULONG ShareAccess,
IN ULONG CreateDisposition,
IN ULONG CreateOptions,
IN PVOID EaBuffer OPTIONAL,
IN ULONG EaLength
);
typedef NTSTATUS (*NTOPENFILE)
(
OUT PHANDLE FileHandle,
IN ACCESS_MASK DesiredAccess,
IN POBJECT_ATTRIBUTES ObjectAttributes,
OUT PIO_STATUS_BLOCK IoStatusBlock,
IN ULONG ShareAccess,
IN ULONG OpenOptions
);
NTSTATUS FakedNtOpenFile
(
OUT PHANDLE FileHandle,
IN ACCESS_MASK DesiredAccess,
IN POBJECT_ATTRIBUTES ObjectAttributes,
OUT PIO_STATUS_BLOCK IoStatusBlock,
IN ULONG ShareAccess,
IN ULONG OpenOptions
);
typedef NTSTATUS (*NTWRITEFILE)
(
IN HANDLE FileHandle,
IN HANDLE Event OPTIONAL,
IN PIO_APC_ROUTINE ApcRoutine OPTIONAL,
IN PVOID ApcContext OPTIONAL,
OUT PIO_STATUS_BLOCK IoStatusBlock,
IN PVOID Buffer,
IN ULONG Length,
IN PLARGE_INTEGER ByteOffset OPTIONAL,
IN PULONG Key OPTIONAL
);
NTSTATUS FakedNtWriteFile
(
IN HANDLE FileHandle,
IN HANDLE Event OPTIONAL,
IN PIO_APC_ROUTINE ApcRoutine OPTIONAL,
IN PVOID ApcContext OPTIONAL,
OUT PIO_STATUS_BLOCK IoStatusBlock,
IN PVOID Buffer,
IN ULONG Length,
IN PLARGE_INTEGER ByteOffset OPTIONAL,
IN PULONG Key OPTIONAL
);
typedef NTSTATUS (*NTDELETEFILE)
(
IN POBJECT_ATTRIBUTES   ObjectAttributes 
);
NTSTATUS FakedNtDeleteFile
(
IN POBJECT_ATTRIBUTES   ObjectAttributes 
);
//����ϵͳ����
NTCREATEFILE RealNtCreateFile;
NTOPENFILE RealNtOpenFile;
NTWRITEFILE RealNtWriteFile;
NTDELETEFILE RealNtDeleteFile;
//��ص�ע����������
typedef NTSTATUS (*NTSETVALUEKEY)
(
IN HANDLE KeyHandle,
IN PUNICODE_STRING ValueName,
IN ULONG TitleIndex,
IN ULONG type1,IN PVOID Data,IN ULONG DataSize
);
NTSTATUS FakedNtSetValueKey
(
IN HANDLE KeyHandle,
IN PUNICODE_STRING ValueName,
IN ULONG TitleIndex,
IN ULONG type1,IN PVOID Data,IN ULONG DataSize
);
typedef NTSTATUS (*NTDELETEVALUEKEY)
(
IN HANDLE KeyHandle,
IN PUNICODE_STRING ValueName
);
NTSTATUS FakedNtDeleteValueKey
(
IN HANDLE KeyHandle,
IN PUNICODE_STRING ValueName
);
typedef NTSTATUS (*NTDELETEKEY)
(
IN HANDLE KeyHandle
);
NTSTATUS FakedNtDeleteKey
(
IN HANDLE KeyHandle
);
typedef NTSTATUS (*NTCREATEKEY)
(
OUT PHANDLE pKeyHandle,
IN ACCESS_MASK DesiredAccess,
IN POBJECT_ATTRIBUTES ObjectAttributes,
IN ULONG TitleIndex,
IN PUNICODE_STRING Class OPTIONAL,
IN ULONG CreateOptions,
OUT PULONG Disposition OPTIONAL
);
NTSTATUS FakedNtCreateKey
(
OUT PHANDLE pKeyHandle,
IN ACCESS_MASK DesiredAccess,
IN POBJECT_ATTRIBUTES ObjectAttributes,
IN ULONG TitleIndex,
IN PUNICODE_STRING Class OPTIONAL,
IN ULONG CreateOptions,
OUT PULONG Disposition OPTIONAL
);
//����ע����ϵͳ����
NTSETVALUEKEY RealNtSetValueKey;
NTDELETEVALUEKEY RealNtDeleteValueKey;
NTDELETEKEY RealNtDeleteKey ;
NTCREATEKEY RealNtCreateKey ;
//�������̼�� ZwCreateProcess
//�ṹ����
typedef NTSTATUS (*ZWCREATEPROCESS)
(
OUT PHANDLE ProcessHandle,
IN ACCESS_MASK DesiredAccess,
IN POBJECT_ATTRIBUTES ObjectAttributes,
IN HANDLE InheritFromProcessHandle,
IN BOOLEAN InheritHandles,
IN HANDLE SectionHandle OPTIONAL,
IN HANDLE DebugPort OPTIONAL,
IN HANDLE ExceptionPort OPTIONAL,
IN HANDLE Unknown 
);
//���庯��
NTSTATUS FakedZwCreateProcess
(
   OUT PHANDLE ProcessHandle,
   IN ACCESS_MASK DesiredAccess,
   IN POBJECT_ATTRIBUTES ObjectAttributes,
   IN HANDLE InheritFromProcessHandle,
   IN BOOLEAN InheritHandles,
   IN HANDLE SectionHandle OPTIONAL,
   IN HANDLE DebugPort OPTIONAL,
   IN HANDLE ExceptionPort OPTIONAL,
   IN HANDLE Unknown 
);
//�������ؼ��ZwLoadDriver
typedef NTSTATUS (*ZWLOADDRIVER)
(
IN PUNICODE_STRING DriverServiceName
);
NTSTATUS FakedZwLoadDriver
(      
IN PUNICODE_STRING DriverServiceName
);
//�򿪽��̼��NtOpenProcess
typedef NTSTATUS (*NTOPENPROCESS)
(
   OUT PHANDLE ProcessHandle, 
   IN ACCESS_MASK AccessMask, 
   IN POBJECT_ATTRIBUTES ObjectAttributes, 
   IN PCLIENT_ID ClientId 
); 
NTSTATUS FakedNtOpenProcess
(
OUT   PHANDLE ProcessHandle, 
IN    ACCESS_MASK DesiredAccess, 
IN    POBJECT_ATTRIBUTES ObjectAttributes, 
IN    PCLIENT_ID ClientId 
);
//������ֹ���ZwTerminateProcess
typedef NTSTATUS (*ZWTERMINATEPROCESS)
(
IN HANDLE      ProcessHandle OPTIONAL,
IN NTSTATUS    ExitStatus 
);
NTSTATUS FakedZwTerminateProcess
(
IN HANDLE      ProcessHandle OPTIONAL,
IN NTSTATUS    ExitStatus 
);
////////////////////����ϵͳ����//////////////////////////////////////////////////////
//ϵͳ����
//ZWSETVALUEKEY RealZwSetValueKey;
ZWCREATEPROCESS RealZwCreateProcess;
ZWLOADDRIVER RealZwLoadDriver;
//���̼��
NTOPENPROCESS RealNtOpenProcess;
ZWTERMINATEPROCESS RealZwTerminateProcess;
PEPROCESS EProcess;
//����HOOK���غ���
void XLM2Hook(BOOL bOnOff);
//ͨ������id����ȡ���̵�����
//void XLPid2Img(ULONG Pid);
typedef struct _SECTION_IMAGE_INFORMATION {
PVOID EntryPoint;
ULONG StackZeroBits;
ULONG StackReserved;
ULONG StackCommit;
ULONG ImageSubsystem;
WORD SubsystemVersionLow;
WORD SubsystemVersionHigh;
ULONG Unknown1;
ULONG ImageCharacteristics;
ULONG ImageMachineType;
ULONG Unknown2[3];
} SECTION_IMAGE_INFORMATION, *PSECTION_IMAGE_INFORMATION;
// Length of process name (rounded up to next DWORD)
#define PROCNAMELEN     20
// Maximum length of NT process name
#define NT_PROCNAMELEN 16
ULONG gProcessNameOffset;
void GetProcessNameOffset()
{
PEPROCESS curproc;
int i;
curproc = PsGetCurrentProcess();
for( i = 0; i < 3*PAGE_SIZE; i++ )
{
   if( !strncmp( "System", (PCHAR) curproc + i, strlen("System") ))
   {
    gProcessNameOffset = i; 
   }
}
}

//extern PServiceDescriptorTableEntry KeServiceDescriptorTable; 
BOOLEAN GetFullName2(HANDLE handle,char * pch)
{
ULONG uactLength;
POBJECT_NAME_INFORMATION pustr;
ANSI_STRING astr;
PVOID pObj; 
NTSTATUS ns;
ns = ObReferenceObjectByHandle( handle, 0, NULL, KernelMode, &pObj, NULL );
if (!NT_SUCCESS(ns))
{
   return FALSE;
}
pustr =(POBJECT_NAME_INFORMATION) ExAllocatePool(NonPagedPool,1024+4);
if (pObj==NULL||pch==NULL)
   return FALSE;
ns = ObQueryNameString(pObj,pustr,512,&uactLength);
if (NT_SUCCESS(ns))
{
   RtlUnicodeStringToAnsiString(&astr,(PUNICODE_STRING)pustr,TRUE);
   //
   strcpy(pch,astr.Buffer);
}
ExFreePool(pustr);
RtlFreeAnsiString( &astr );
if (pObj)
{
   ObDereferenceObject(pObj);
}
return TRUE;
}
BOOLEAN GetPath(char *strPath,HANDLE hHandle)
{
ULONG uactLength;
POBJECT_NAME_INFORMATION pustr;
ANSI_STRING astr;
PVOID pObj;
NTSTATUS ns;
ns = ObReferenceObjectByHandle( hHandle, 0, NULL, KernelMode, &pObj, NULL );
if (!NT_SUCCESS(ns))
{
   return FALSE;
}
pustr = (POBJECT_NAME_INFORMATION)ExAllocatePool(NonPagedPool,1024+4);
if (pObj==NULL||strPath==NULL)
   return FALSE;
ns = ObQueryNameString(pObj,pustr,512,&uactLength);
if (NT_SUCCESS(ns))
{
   RtlUnicodeStringToAnsiString(&astr,(PUNICODE_STRING)pustr,TRUE);
   //
   strcpy(strPath,astr.Buffer);
}
ExFreePool(pustr);
RtlFreeAnsiString( &astr );
if (pObj)
{
   ObDereferenceObject(pObj);
}
return TRUE;
}
//KeyHandle��hSection   
NTSTATUS GetFullName(HANDLE     KeyHandle,char   *fullname)   
{   
NTSTATUS   ns;   
PVOID   pKey=NULL,pFile=NULL;   
UNICODE_STRING fullUniName;   
ANSI_STRING   akeyname;   
ULONG   actualLen;   
UNICODE_STRING   dosName;   
fullUniName.Buffer=NULL;   
fullUniName.Length=0;   
fullname[0]=0x00;   
ns=   ObReferenceObjectByHandle(KeyHandle,0,NULL,KernelMode,&pKey,NULL);   
if(   !NT_SUCCESS(ns))   return   ns;   
fullUniName.Buffer   =(PWSTR) ExAllocatePool(PagedPool,MAXPATHLEN*2);//1024*2   
fullUniName.MaximumLength   =   MAXPATHLEN*2;   
__try   
{   
   pFile=(PVOID)*(ULONG   *)((char   *)pKey+20);   
   pFile=(PVOID)*(ULONG   *)((char   *)pFile);   
   pFile=(PVOID)*(ULONG   *)((char   *)pFile+36);   
   ObReferenceObjectByPointer(pFile,   0,   NULL,   KernelMode);   
   RtlVolumeDeviceToDosName(((PFILE_OBJECT)pFile)->DeviceObject,&dosName);   
   //ns=ObQueryNameString(   pFile,   fullUniName,   MAXPATHLEN,   &actualLen   );   
   RtlCopyUnicodeString(&fullUniName,   &dosName);   
   RtlAppendUnicodeStringToString(&fullUniName,&((PFILE_OBJECT)pFile)->FileName);   
   ObDereferenceObject(pFile);   
   ObDereferenceObject(pKey);   
   RtlUnicodeStringToAnsiString(   &akeyname,   &fullUniName,   TRUE   );   
   if(akeyname.Length<MAXPATHLEN)     
   {   
    memcpy(fullname,akeyname.Buffer,akeyname.Length);   
    fullname[akeyname.Length]=0x00;   
   }   
   else   
   {   
    memcpy(fullname,akeyname.Buffer,MAXPATHLEN);   
    fullname[MAXPATHLEN-1]=0x00;   
   }   
   RtlFreeAnsiString(   &akeyname   );   
   ExFreePool(dosName.Buffer);   
   ExFreePool(   fullUniName.Buffer   );   
   return   STATUS_SUCCESS;   
}   
__except(1)   
{   
   if(fullUniName.Buffer)   ExFreePool(   fullUniName.Buffer     );   
   if(pKey)   ObDereferenceObject(pKey   );   
   return   STATUS_SUCCESS;   
}   
} 
//ͨ��ƫ������ȡ����ǰ���������ƣ�������
BOOL GetProcessName( PCHAR theName )
{
PEPROCESS       curproc;
char            *nameptr;
ULONG           i;
KIRQL           oldirql;
if( gProcessNameOffset )
{
   curproc = PsGetCurrentProcess();
   nameptr   = (PCHAR) curproc + gProcessNameOffset;
   strncpy( theName, nameptr, NT_PROCNAMELEN );
   theName[NT_PROCNAMELEN] = 0; /* NULL at end */
   return TRUE;
}
return FALSE;
}
//ͨ�������ȡע���·��
//��ȡdll�еĵ���������ַMAP
DWORD GetDllFunctionAddress(char* lpFunctionName, PUNICODE_STRING pDllName)
{
HANDLE hThread, hSection, hFile, hMod;
SECTION_IMAGE_INFORMATION sii;
IMAGE_DOS_HEADER* dosheader;
IMAGE_OPTIONAL_HEADER* opthdr;
IMAGE_EXPORT_DIRECTORY* pExportTable;
DWORD* arrayOfFunctionAddresses;
DWORD* arrayOfFunctionNames;
WORD* arrayOfFunctionOrdinals;
DWORD functionOrdinal;
DWORD Base, x, functionAddress;
char* functionName;
STRING ntFunctionName, ntFunctionNameSearch;
PVOID BaseAddress = NULL;
SIZE_T size=0;
OBJECT_ATTRIBUTES oa = {sizeof oa, 0, pDllName, OBJ_CASE_INSENSITIVE};
IO_STATUS_BLOCK iosb;
//_asm int 3;
ZwOpenFile(&hFile, FILE_EXECUTE | SYNCHRONIZE, &oa, &iosb, FILE_SHARE_READ, FILE_SYNCHRONOUS_IO_NONALERT);
oa.ObjectName = 0;
ZwCreateSection(&hSection, SECTION_ALL_ACCESS, &oa, 0,PAGE_EXECUTE, SEC_IMAGE, hFile);
ZwMapViewOfSection(hSection, NtCurrentProcess(), &BaseAddress, 0, 1000, 0, &size, (SECTION_INHERIT)1, MEM_TOP_DOWN, PAGE_READWRITE);
ZwClose(hFile);
hMod = BaseAddress;
dosheader = (IMAGE_DOS_HEADER *)hMod;
opthdr =(IMAGE_OPTIONAL_HEADER *) ((BYTE*)hMod+dosheader->e_lfanew+24);
pExportTable =(IMAGE_EXPORT_DIRECTORY*)((BYTE*) hMod + opthdr->DataDirectory[ IMAGE_DIRECTORY_ENTRY_EXPORT]. VirtualAddress);
// now we can get the exported functions, but note we convert from RVA to address
arrayOfFunctionAddresses = (DWORD*)( (BYTE*)hMod + pExportTable->AddressOfFunctions);
arrayOfFunctionNames = (DWORD*)( (BYTE*)hMod + pExportTable->AddressOfNames);
arrayOfFunctionOrdinals = (WORD*)( (BYTE*)hMod + pExportTable->AddressOfNameOrdinals);
Base = pExportTable->Base;
RtlInitString(&ntFunctionNameSearch, lpFunctionName);
for(x = 0; x < pExportTable->NumberOfFunctions; x++)
{
   functionName = (char*)( (BYTE*)hMod + arrayOfFunctionNames[x]);
   RtlInitString(&ntFunctionName, functionName);
   functionOrdinal = arrayOfFunctionOrdinals[x] + Base - 1; // always need to add base, -1 as array counts from 0
   // this is the funny bit. you would expect the function pointer to simply be arrayOfFunctionAddresses[x]...
   // oh no... thats too simple. it is actually arrayOfFunctionAddresses[functionOrdinal]!!
   functionAddress = (DWORD)( (BYTE*)hMod + arrayOfFunctionAddresses[functionOrdinal]);
   if (RtlCompareString(&ntFunctionName, &ntFunctionNameSearch, TRUE) == 0)
   {
    ZwClose(hSection);
    return functionAddress;
   }
}
ZwClose(hSection);
return 0;
}
int ConvertFileNameWCHARToCHAR(PWCHAR pWChar,PCHAR pChar) 
{ 
UNICODE_STRING usFileName; 
ANSI_STRING asFileName; 
RtlInitUnicodeString(&usFileName, pWChar); 
asFileName.Length = 0; 
asFileName.MaximumLength = MAXPATHLEN; 
asFileName.Buffer = pChar; 
RtlUnicodeStringToAnsiString(&asFileName, &usFileName, FALSE); 
pChar[asFileName.Length] = 0; 
return asFileName.Length; 
}
//ж������
VOID ssdthookOnUnload(  )
{
	XLM2Hook(FALSE);
	zwprint("ssdthookOnUnload  leaver");
	return ;
/*UNICODE_STRING devlink;
DbgPrint("XLM:INFO: OnUnload called\n");
//ֹͣHOOK���ָ�SSDT��ϵͳ������ַ
XLM2Hook(FALSE);
RtlInitUnicodeString(&devlink,XLMonitor_DOS_DEVICE_NAME_W);
IoDeleteSymbolicLink(&devlink);
if (DriverObject->DeviceObject)
{
   IoDeleteDevice(DriverObject->DeviceObject); //
}
*/
}
////////////////////������ں���//////////////////////////////////////////////////////
NTSTATUS ssdthookDriverEntry(  )
{
int i;
UNICODE_STRING dllName;
DWORD functionAddress;
UNICODE_STRING devname;
UNICODE_STRING devlink;
PDEVICE_OBJECT devob ;
NTSTATUS status ;
/*
//_asm int 3;
DbgPrint("XLM:INFO:Driver Loaded Success");
RtlInitUnicodeString(&devname,XLMonitor_DEVICE_NAME_W);
RtlInitUnicodeString(&devlink,XLMonitor_DOS_DEVICE_NAME_W);
//�����豸����
status = IoCreateDevice(theDriverObject,
   256,
   &devname,
   FILE_DEVICE_XLMonitor,
   0,
   TRUE,
   &devob);
if (!NT_SUCCESS(status))
{
   DbgPrint(("XLM:INFO:Failed To Create Device"));
   return status ;
}
status = IoCreateSymbolicLink(&devlink,&devname);
if (!NT_SUCCESS(status))
{
   DbgPrint(("XLM:INFO:Failed To Create Symboliclink"));
   IoDeleteDevice(devob);
   return status;
}
//��������ж�ص�ʱ���ֹͣHOOK
*/
//theDriverObject->DriverUnload = OnUnload;
GetProcessNameOffset();
zwprint("enter    ssdthookDriverEntry");
//////////////////////////HOOK SSDT ϵͳ����////////////////////////////////////////////////
RtlInitUnicodeString(&dllName, L"\\Device\\HarddiskVolume1\\Windows\\System32\\ntdll.dll");
//��ȡSSDT��ָ��ϵͳ�����ĵ�ַƫ������
//ZwCreateProcessEx
functionAddress = GetDllFunctionAddress("ZwCreateProcessEx", &dllName);
position = *((WORD*)(functionAddress+1));
//ZwSetValueKey
//functionAddress = GetDllFunctionAddress("ZwSetValueKey",&dllName);
//pos = *((WORD*)(functionAddress+1));
functionAddress = GetDllFunctionAddress("NtSetValueKey",&dllName);
inxNtSetValueKey = *((WORD *)(functionAddress+1));
zwprint("inxNtSetValueKey");
zwprinti((int)inxNtSetValueKey);
//ZwLoadDriver
/*
functionAddress = GetDllFunctionAddress("ZwLoadDriver",&dllName);
po = *((WORD *)(functionAddress+1));
//NtOpenProcess
functionAddress = GetDllFunctionAddress("NtOpenProcess",&dllName);
ps = *((WORD *)(functionAddress+1));
//ZwTerminateProcess
functionAddress = GetDllFunctionAddress("ZwTerminateProcess",&dllName);
pts = *((WORD *)(functionAddress+1));
//NtSetValueKey
functionAddress = GetDllFunctionAddress("NtSetValueKey",&dllName);
inxNtSetValueKey = *((WORD *)(functionAddress+1));
//NtDeleteValueKey
functionAddress = GetDllFunctionAddress("NtDeleteValueKey",&dllName);
inxNtDeleteValueKey = *((WORD *)(functionAddress+1));
//NtDeleteKey
functionAddress = GetDllFunctionAddress("NtDeleteKey",&dllName);
inxNtDeleteKey = *((WORD *)(functionAddress+1));
//NtCreateKey
functionAddress = GetDllFunctionAddress("NtCreateKey",&dllName);
inxNtCreateKey = *((WORD *)(functionAddress+1));
//NtCreateFile
functionAddress = GetDllFunctionAddress("NtCreateFile",&dllName);
inxNtCreateFile = *((WORD *)(functionAddress+1));
//NtOpenFile
functionAddress = GetDllFunctionAddress("NtOpenFile",&dllName);
inxNtOpenFile = *((WORD *)(functionAddress+1));
//NtWriteFile
functionAddress = GetDllFunctionAddress("NtWriteFile",&dllName);
inxNtWriteFile = *((WORD *)(functionAddress+1));
//NtDeleteFile
functionAddress = GetDllFunctionAddress("NtDeleteFile",&dllName);
inxNtDeleteFile = *((WORD *)(functionAddress+1));
*/
//���������Ϣ
//���溯����ַ= ����ַ+ƫ��
RealZwCreateProcess = (ZWCREATEPROCESS)(*(((PServiceDescriptorTableEntry)KeServiceDescriptorTable)->ServiceTableBase + position));
RealNtSetValueKey = (NTSETVALUEKEY)(*(((PServiceDescriptorTableEntry)KeServiceDescriptorTable)->ServiceTableBase + inxNtSetValueKey));
//RealZwSetValueKey =   (ZWSETVALUEKEY)(*(((PServiceDescriptorTableEntry)KeServiceDescriptorTable)->ServiceTableBase + pos));
//��ȡ����ע�������ַ�ķ������ر�
//pos = *((WORD*)((DWORD)ZwSetValueKey+1));
//RealZwLoadDriver =   (ZWLOADDRIVER)(*(((PServiceDescriptorTableEntry)KeServiceDescriptorTable)->ServiceTableBase + po));
//NtOpenProcess
/*
RealNtOpenProcess = (NTOPENPROCESS)(*(((PServiceDescriptorTableEntry)KeServiceDescriptorTable)->ServiceTableBase + ps));
//ZwTerminateProcess
RealZwTerminateProcess = (ZWTERMINATEPROCESS)(*(((PServiceDescriptorTableEntry)KeServiceDescriptorTable)->ServiceTableBase +pts));
//NtSetValueKey
RealNtSetValueKey = (NTSETVALUEKEY)(*(((PServiceDescriptorTableEntry)KeServiceDescriptorTable)->ServiceTableBase + inxNtSetValueKey));
//NtDeleteValueKey
RealNtDeleteValueKey = (NTDELETEVALUEKEY)(*(((PServiceDescriptorTableEntry)KeServiceDescriptorTable)->ServiceTableBase + inxNtDeleteValueKey));
//NtDeleteKey
RealNtDeleteKey = (NTDELETEKEY)(*(((PServiceDescriptorTableEntry)KeServiceDescriptorTable)->ServiceTableBase + inxNtDeleteKey));
//NtCreateKey
RealNtCreateKey = (NTCREATEKEY)(*(((PServiceDescriptorTableEntry)KeServiceDescriptorTable)->ServiceTableBase + inxNtCreateKey));

//NtCreateFile
RealNtCreateFile = (NTCREATEFILE)(*(((PServiceDescriptorTableEntry)KeServiceDescriptorTable)->ServiceTableBase + inxNtCreateFile));
//NtOpenFile
RealNtOpenFile = (NTOPENFILE)(*(((PServiceDescriptorTableEntry)KeServiceDescriptorTable)->ServiceTableBase + inxNtOpenFile));
//NtWriteFile
RealNtWriteFile = (NTWRITEFILE)(*(((PServiceDescriptorTableEntry)KeServiceDescriptorTable)->ServiceTableBase + inxNtWriteFile));
//NtDeleteFile
RealNtDeleteFile = (NTDELETEFILE)(*(((PServiceDescriptorTableEntry)KeServiceDescriptorTable)->ServiceTableBase + inxNtDeleteFile));
//�������ص�ʱ��Ϳ�ʼHOOK����ʱ�ѻ�ȡ����ַ
*/
XLM2Hook(TRUE);
zwprint("leaver    ssdthookDriverEntry");

return STATUS_SUCCESS;
}
////////////////////////////�滻������ʵ��//////////////////////////////////////////////
//�滻�������̵ĺ���
NTSTATUS FakedZwCreateProcess(
         OUT PHANDLE ProcessHandle,
         IN ACCESS_MASK DesiredAccess,
         IN POBJECT_ATTRIBUTES ObjectAttributes,
         IN HANDLE InheritFromProcessHandle,
         IN BOOLEAN InheritHandles,
         IN HANDLE SectionHandle OPTIONAL,
         IN HANDLE DebugPort OPTIONAL,
         IN HANDLE ExceptionPort OPTIONAL,
         IN HANDLE Unknown 
         )
{
char aProcessName[PROCNAMELEN];
char aPathName[MAXPATHLEN];
//��ȡ��ǰ��������
GetProcessName(aProcessName);
GetFullName(SectionHandle,aPathName);
DbgPrint("XLM:PS:ZwCreateProcess:%s Path:%s\n",aProcessName,aPathName);
//DbgPrint("XLM:The name is %s\n",aPathName);
//ֻ�����ؽ�����Ϣ�󣬼���ִ��ϵͳԭʼ�ú���
return RealZwCreateProcess(
   ProcessHandle,
   DesiredAccess,
   ObjectAttributes,
   InheritFromProcessHandle,
   InheritHandles,
   SectionHandle,
   DebugPort,
   ExceptionPort,
   Unknown 
   );
/*
ProcessHandle = NULL;
return STATUS_SUCCESS;
*/
} 
NTSTATUS FakedZwLoadDriver(IN PUNICODE_STRING DriverServiceName )
{
char aProcessName[PROCNAMELEN];
char aDrvname[MAXPATHLEN];
ANSI_STRING ansi ;
GetProcessName(aProcessName);
RtlUnicodeStringToAnsiString(&ansi,DriverServiceName,TRUE);
if(ansi.Length<MAXPATHLEN)     
{   
   memcpy(aDrvname,ansi.Buffer,ansi.Length);   
   aDrvname[ansi.Length]=0x00;   
}   
else   
{   
   memcpy(aDrvname,ansi.Buffer,MAXPATHLEN);   
   aDrvname[MAXPATHLEN-1]=0x00;   
}   
RtlFreeAnsiString( &ansi); 
DbgPrint("XLM:DRV:ZwLoadDriver:%s Name:%s\n",aProcessName,aDrvname);
//DbgPrint("XLM:Driver name is %s\n",aDrvname);
return RealZwLoadDriver(
   DriverServiceName 
   );
// return STATUS_ACCESS_DENIED;
}
NTSTATUS FakedNtOpenProcess(
        OUT PHANDLE ProcessHandle, 
        IN ACCESS_MASK DesiredAccess, 
        IN POBJECT_ATTRIBUTES ObjectAttributes, 
        IN PCLIENT_ID ClientId )
{ 
ULONG Pid; 
char aProcessName[PROCNAMELEN];
char aPathName[MAXPATHLEN];
//��ȡ��ǰ��������
GetProcessName(aProcessName);
DbgPrint( "NtOpenProcess() called.\n" ); 
Pid = (ULONG)ClientId->UniqueProcess; 
DbgPrint( "XLM:PS:Path %s Pid %d.\n",aProcessName,Pid ); 
return (NTSTATUS)(NTOPENPROCESS)RealNtOpenProcess( 
   ProcessHandle, 
   DesiredAccess, 
   ObjectAttributes, 
   ClientId
   ); 
} 
NTSTATUS FakedZwTerminateProcess
(
IN HANDLE ProcessHandle OPTIONAL,
IN NTSTATUS ExitStatus 
)
{
char aProcessName[PROCNAMELEN];
char aPathName[MAXPATHLEN];
GetProcessName(aProcessName);
DbgPrint("XLM:PS:ZwTerminateProcess:Path %s\n",aProcessName);
return (NTSTATUS)(ZWTERMINATEPROCESS)RealZwTerminateProcess(
   ProcessHandle,
   ExitStatus
   );
}
 NTSTATUS FakedNtSetValueKey
(
IN HANDLE KeyHandle,
IN PUNICODE_STRING ValueName, 
IN ULONG TitleIndex OPTIONAL, 
IN ULONG Type,
IN PVOID Data, 
IN ULONG DataSize 
)
{
char strName[512];
char aProcessName[PROCNAMELEN];
char   buff[1000];
int status  =1;
char  buff_2[102];
GetPath(strName,KeyHandle);
GetProcessName(aProcessName);
zwfile_read(0,buff_2);
if(strstr(buff_2,"0")) status = 0;
else {
	if(strstr(buff_2,aProcessName)){
		status = 0;
	}
}
if(status==0){
zwprint("FakedNtSetValueKey  -----------ssssss--------------====================>");
DbgPrint("XLM:REG:NtSetValueKey:ProcessName: %s",aProcessName);

// ��ȡע�������·�����������ļ���
if(Type == 4 || Type == 5 || Type == 11)  {
   DbgPrint("XLM:REG:NtSetValueKey:KeyPath:%s KeyName:%S %d %x\n",strName,ValueName->Buffer,*(DWORD*)Data,*(DWORD*)Data); 
   sprintf(buff,"XLM:REG:NtSetValueKey:KeyPath:%s KeyName:%S %d %x\n",strName,ValueName->Buffer,*(DWORD*)Data,*(DWORD*)Data);
   
 }
else if(Type == 3){
   DbgPrint("XLM:REG:NtSetValueKey:KeyPath:%s KeyName:%S\n",strName,ValueName->Buffer);
      sprintf(buff,"XLM:REG:NtSetValueKey:KeyPath:%s KeyName:%S\n",strName,ValueName->Buffer);
}
else if(Type == 8){
   DbgPrint("XLM:REG:NtSetValueKey:KeyPath:%s KeyName:%S\n",strName,ValueName->Buffer);
      sprintf(buff,"XLM:REG:NtSetValueKey:KeyPath:%s KeyName:%S \n",strName,ValueName->Buffer);
}
else{
   DbgPrint("XLM:REG:NtSetValueKey:KeyPath:%s KeyName:%S\n",strName,ValueName->Buffer);
    sprintf(buff,"XLM:REG:NtSetValueKey:KeyPath:%s KeyName:%S \n",strName,ValueName->Buffer);
     }

 
 zwprint("FakedNtSetValueKey  --------------------------->");
}else{
	
}
zwfile_write(0,buff);  
return RealNtSetValueKey(
   KeyHandle,
   ValueName,
   TitleIndex,
   Type,
   Data,
   DataSize);
}
NTSTATUS FakedNtCreateKey
(
OUT PHANDLE pKeyHandle, 
IN ACCESS_MASK DesiredAccess, 
IN POBJECT_ATTRIBUTES ObjectAttributes, 
IN ULONG TitleIndex, 
IN PUNICODE_STRING Class OPTIONAL, 
IN ULONG CreateOptions, 
OUT PULONG Disposition OPTIONAL 
)
{
char strName[512];
char aProcessName[PROCNAMELEN];
//��ȡ������·��
GetPath(strName,ObjectAttributes->RootDirectory);
GetProcessName(aProcessName);
DbgPrint("XLM:REG:NtCreateKey:ProcessName: %s,SubKey:%s KeyName:%s\n",aProcessName,strName,ObjectAttributes->ObjectName->Buffer);
//��ȡע�������·�����������ļ���

//DbgPrint("XLM:REG:NtCreateKey:SubKey:%s KeyName:%S.\n",strName,ObjectAttributes->ObjectName->Buffer);
return (NTSTATUS)(NTCREATEKEY)RealNtCreateKey(
   pKeyHandle,
   DesiredAccess,
   ObjectAttributes,
   TitleIndex,
   Class OPTIONAL,
   CreateOptions,
   Disposition OPTIONAL
   );
}
NTSTATUS FakedNtDeleteKey(IN HANDLE KeyHandle )
{
char strObjectPath[512] = {'\0'};
char aProcessName[PROCNAMELEN];
GetPath(strObjectPath,KeyHandle);
GetProcessName(aProcessName);
DbgPrint("XLM:REG:NtDeleteKey:ProcessName: %s Key:%s\n",aProcessName,strObjectPath);
//DbgPrint("XLM:NtDeleteKey:KeyName:%s\n",strObjectPath);
return (NTSTATUS)(NTDELETEKEY)RealNtDeleteKey(KeyHandle);
}
NTSTATUS FakedNtDeleteValueKey(IN HANDLE KeyHandle,IN PUNICODE_STRING ValueName )
{
char strName[512];
char aProcessName[PROCNAMELEN];
GetPath(strName,KeyHandle);
GetProcessName(aProcessName);
DbgPrint("XLM:REG:NtDeleteValueKey:ProcessName: %s SubKey:%s KeyName:%s\n",aProcessName,strName,ValueName->Buffer);

//��ȡע�������·�����������ļ���
//DbgPrint("XLM:DeleteValueKey:SubKey:%s KeyName%S.\n",strName,ValueName->Buffer);
return (NTSTATUS)(NTDELETEVALUEKEY)RealNtDeleteValueKey(KeyHandle,ValueName);
}
//////////////////////////////////////////////////////////////////////////
NTSTATUS FakedNtCreateFile(
OUT PHANDLE FileHandle, 
IN ACCESS_MASK DesiredAccess, 
IN POBJECT_ATTRIBUTES ObjectAttributes,
OUT PIO_STATUS_BLOCK IoStatusBlock, 
IN PLARGE_INTEGER AllocationSize OPTIONAL, 
IN ULONG FileAttributes,
IN ULONG ShareAccess, 
IN ULONG CreateDisposition, 
IN ULONG CreateOptions, 
IN PVOID EaBuffer OPTIONAL, 
IN ULONG EaLength )
{
char aFullPath[MAXPATHLEN];
char aProcessName[PROCNAMELEN];
GetProcessName(aProcessName);

//DbgPrint("XLM:CreateFile %S\n",ObjectAttributes->ObjectName->Buffer);
ConvertFileNameWCHARToCHAR(ObjectAttributes->ObjectName->Buffer,aFullPath);
//DbgPrint("XLM:CreateFile %s\n",aFullPath);
DbgPrint("XLM:FILE:NtCreateFile ProcessName: %s CreateFile:%s\n",aProcessName,aFullPath);

return RealNtCreateFile(
   FileHandle, 
   DesiredAccess, 
   ObjectAttributes,
   IoStatusBlock, 
   AllocationSize OPTIONAL, 
   FileAttributes,
   ShareAccess, 
   CreateDisposition, 
   CreateOptions, 
   EaBuffer OPTIONAL, 
   EaLength );
}
NTSTATUS FakedNtOpenFile(
OUT PHANDLE FileHandle, 
IN ACCESS_MASK DesiredAccess, 
IN POBJECT_ATTRIBUTES ObjectAttributes, 
OUT PIO_STATUS_BLOCK IoStatusBlock, 
IN ULONG ShareAccess,
IN ULONG OpenOptions 
)
{
//char aProcessName[PROCNAMELEN];
//GetProcessName(aProcessName);
//DbgPrint("XLM:ProcessName: %s Call NtOpenFile\n",aProcessName);
//DbgPrint("XLM:OpenFile %S\n",ObjectAttributes->ObjectName->Buffer);
return RealNtOpenFile(
   FileHandle, 
   DesiredAccess, 
   ObjectAttributes, 
   IoStatusBlock, 
   ShareAccess,
   OpenOptions 
   );
}
//��ȡɾ�����ļ�����Ϣ��������п���������
NTSTATUS FakedNtWriteFile(
IN HANDLE FileHandle, 
IN HANDLE Event OPTIONAL, 
IN PIO_APC_ROUTINE ApcRoutine OPTIONAL, 
IN PVOID ApcContext OPTIONAL, 
OUT PIO_STATUS_BLOCK IoStatusBlock, 
IN PVOID Buffer, 
IN ULONG Length, 
IN PLARGE_INTEGER ByteOffset OPTIONAL, 
IN PULONG Key OPTIONAL 
)
{
char aProcessName[PROCNAMELEN];
FILE_INFORMATION_CLASS FileInformationClass = FileNameInformation ;
if ( FileHandle != NULL)
{
   NTSTATUS nts = STATUS_UNSUCCESSFUL;
   IO_STATUS_BLOCK iosb ={ 0,0 };
   PWCHAR pstring = NULL;
   ANSI_STRING    ansiUndeleteFileName ;//
   UNICODE_STRING usFileName ={ 0,0,0 }; //
   PFILE_NAME_INFORMATION pFileInfo = NULL;
   RtlInitEmptyUnicodeString( &usFileName,'\0',0 );
   pFileInfo = (PFILE_NAME_INFORMATION) ExAllocatePool( 
    PagedPool, 
    sizeof(FILE_NAME_INFORMATION) + MAXPATHLEN
    );
   if ( NULL == pFileInfo )
   {
    return STATUS_INSUFFICIENT_RESOURCES;
   }//if ( NULL == pfni )
   RtlZeroMemory( pFileInfo ,sizeof(FILE_NAME_INFORMATION) + MAXPATHLEN );
   nts = ZwQueryInformationFile(   
    FileHandle,
    &iosb, 
    pFileInfo,
    sizeof(FILE_NAME_INFORMATION) + MAXPATHLEN, 
    FileNameInformation
    );
   if ( !NT_SUCCESS(nts) )
   {
    ExFreePool(pFileInfo);
    pFileInfo = NULL;
    return nts; 
   } 
   else
   {
    ANSI_STRING ansiDesFileName={0,0,0}; 
    PWSTR pwstr=NULL;
    ULONG len =0;
    pwstr= wcsrchr( pFileInfo->FileName, L'\\' );
    RtlInitUnicodeString(&usFileName, pwstr+1); // uniFileName �����ͷ�
    RtlUnicodeStringToAnsiString(&ansiDesFileName, &usFileName, TRUE); // TRUE, �����ͷ�
    // ��ӡ���, ��debugview ���Բ鿴��ӡ���
    GetProcessName(aProcessName);
    if (strncmp(aProcessName,"lsass.exe",strlen("lsass.exe")))
     if (strncmp(aProcessName,"System",strlen("System")))
     {
      DbgPrint("XLM:FILE:NtWriteFile:ProcessName: %s ansiFileName:%s\n",aProcessName,ansiDesFileName.Buffer);
    
      //DbgPrint(("ansiFileName :%s\n", ansiDesFileName.Buffer)); 
     }
   }
//////////////////////////////////////////////////////////////////////////
}
return RealNtWriteFile(
   FileHandle, 
   Event OPTIONAL, 
   ApcRoutine OPTIONAL, 
   ApcContext OPTIONAL, 
   IoStatusBlock, 
   Buffer, 
   Length, 
   ByteOffset OPTIONAL, 
   Key OPTIONAL 
   );
}
NTSTATUS FakedNtDeleteFile(IN POBJECT_ATTRIBUTES ObjectAttributes )
{
char aProcessName[PROCNAMELEN];
GetProcessName(aProcessName);
DbgPrint("XLM:FILE:NtDeleteFile ProcessName: %s DeleteFile %s\n",aProcessName,ObjectAttributes->ObjectName->Buffer);
//DbgPrint("XLM:DeleteFile %S\n",ObjectAttributes->ObjectName->Buffer);


return RealNtDeleteFile(ObjectAttributes );
}
///////////////////////������ر�HOOK ���ܣ��滻ϵͳ������SSDT��ַ///////////////////////////////////////////////////
void XLM2Hook(BOOL bOnOff)
{
//ȥ��д����AND
_asm
{
   CLI                    //disable interrupt
   MOV    EAX, CR0        //move CR0 register into EAX
   AND EAX, NOT 10000H //disable WP bit
   MOV    CR0, EAX        //write register back
}
if (bOnOff)
{
   DbgPrint("XLM:INFO:Start Hook\n");
   //��Ҫ�滻��ַ�ĺ�����
   /*(ZWCREATEPROCESS)*/(*(((PServiceDescriptorTableEntry)KeServiceDescriptorTable)->ServiceTableBase + position)) = (unsigned int)FakedZwCreateProcess ; 
   /* (NTSETVALUEKEY)*/(*(((PServiceDescriptorTableEntry)KeServiceDescriptorTable)->ServiceTableBase + inxNtSetValueKey)) =(unsigned int) FakedNtSetValueKey;
//  (ZWLOADDRIVER)(*(((PServiceDescriptorTableEntry)KeServiceDescriptorTable)->ServiceTableBase + po)) = FakedZwLoadDriver ;
   //(NTOPENPROCESS)(*(((PServiceDescriptorTableEntry)KeServiceDescriptorTable)->ServiceTableBase + ps)) = FakedNtOpenProcess ;
  /* (ZWTERMINATEPROCESS)(*(((PServiceDescriptorTableEntry)KeServiceDescriptorTable)->ServiceTableBase + pts)) = FakedZwTerminateProcess;
   (NTCREATEKEY)(*(((PServiceDescriptorTableEntry)KeServiceDescriptorTable)->ServiceTableBase + inxNtCreateKey)) = FakedNtCreateKey;
   (NTDELETEKEY)(*(((PServiceDescriptorTableEntry)KeServiceDescriptorTable)->ServiceTableBase + inxNtDeleteKey)) = FakedNtDeleteKey;
   (NTDELETEVALUEKEY)(*(((PServiceDescriptorTableEntry)KeServiceDescriptorTable)->ServiceTableBase + inxNtDeleteValueKey)) = FakedNtDeleteValueKey;
   (NTSETVALUEKEY)(*(((PServiceDescriptorTableEntry)KeServiceDescriptorTable)->ServiceTableBase + inxNtSetValueKey)) = FakedNtSetValueKey;
   //NtCreateFile
   (NTCREATEFILE)(*(((PServiceDescriptorTableEntry)KeServiceDescriptorTable)->ServiceTableBase + inxNtCreateFile)) = FakedNtCreateFile;
   //NtOpenFile
   (NTOPENFILE)(*(((PServiceDescriptorTableEntry)KeServiceDescriptorTable)->ServiceTableBase + inxNtOpenFile)) = FakedNtOpenFile;
   //NtWriteFile
   (NTWRITEFILE)(*(((PServiceDescriptorTableEntry)KeServiceDescriptorTable)->ServiceTableBase + inxNtWriteFile)) = FakedNtWriteFile;
   //NtDeleteFile
   (NTDELETEFILE)(*(((PServiceDescriptorTableEntry)KeServiceDescriptorTable)->ServiceTableBase + inxNtDeleteFile)) = FakedNtDeleteFile;
*/
}
else 
{
   DbgPrint("XLM:INFO:Stop Hook\n");
   //��Ҫ�ָ�HOOK �ĺ���
   /*(ZWCREATEPROCESS)*/(*(((PServiceDescriptorTableEntry)KeServiceDescriptorTable)->ServiceTableBase + position)) =(unsigned int) RealZwCreateProcess ;
    //  (ZWCREATEPROCESS)(*(((PServiceDescriptorTableEntry)KeServiceDescriptorTable)->ServiceTableBase + pos)) = RealZwCreateProcess ;
   /*(NTSETVALUEKEY)*/(*(((PServiceDescriptorTableEntry)KeServiceDescriptorTable)->ServiceTableBase + inxNtSetValueKey)) =(unsigned int) RealNtSetValueKey;

   //(ZWLOADDRIVER)(*(((PServiceDescriptorTableEntry)KeServiceDescriptorTable)->ServiceTableBase + po)) = RealZwLoadDriver ;
 /*  //(NTOPENPROCESS)(*(((PServiceDescriptorTableEntry)KeServiceDescriptorTable)->ServiceTableBase + ps)) = RealNtOpenProcess ;
   (ZWTERMINATEPROCESS)(*(((PServiceDescriptorTableEntry)KeServiceDescriptorTable)->ServiceTableBase + pts)) = RealZwTerminateProcess;
   (NTCREATEKEY)(*(((PServiceDescriptorTableEntry)KeServiceDescriptorTable)->ServiceTableBase + inxNtCreateKey)) = RealNtCreateKey;
   (NTDELETEKEY)(*(((PServiceDescriptorTableEntry)KeServiceDescriptorTable)->ServiceTableBase + inxNtDeleteKey)) = RealNtDeleteKey;
   (NTDELETEVALUEKEY)(*(((PServiceDescriptorTableEntry)KeServiceDescriptorTable)->ServiceTableBase + inxNtDeleteValueKey)) = RealNtDeleteValueKey;
   (NTSETVALUEKEY)(*(((PServiceDescriptorTableEntry)KeServiceDescriptorTable)->ServiceTableBase + inxNtSetValueKey)) = RealNtSetValueKey;
   //NtCreateFile
   (NTCREATEFILE)(*(((PServiceDescriptorTableEntry)KeServiceDescriptorTable)->ServiceTableBase + inxNtCreateFile)) = RealNtCreateFile;
   //NtOpenFile
   (NTOPENFILE)(*(((PServiceDescriptorTableEntry)KeServiceDescriptorTable)->ServiceTableBase + inxNtOpenFile)) = RealNtOpenFile;
   //NtWriteFile
   (NTWRITEFILE)(*(((PServiceDescriptorTableEntry)KeServiceDescriptorTable)->ServiceTableBase + inxNtWriteFile)) = RealNtWriteFile;
   //NtDeleteFile
   (NTDELETEFILE)(*(((PServiceDescriptorTableEntry)KeServiceDescriptorTable)->ServiceTableBase + inxNtDeleteFile)) = RealNtDeleteFile;
*/
}
//�ָ�д����OR
_asm
{
   MOV    EAX, CR0        //move CR0 register into EAX
   OR    EAX, 10000H        //enable WP bit     
   MOV    CR0, EAX        //write register back        
   STI                    //enable interrupt
}
}





