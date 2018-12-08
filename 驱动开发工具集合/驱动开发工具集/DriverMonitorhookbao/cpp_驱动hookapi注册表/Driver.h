/************************************************************************
* �ļ�����:Driver.h                                                 
* ��    ��:�ŷ�
* �������:2007-11-1
*************************************************************************/
#pragma once

#ifdef __cplusplus
extern "C"
{
#endif
#include <NTDDK.h>
#ifdef __cplusplus
}
#endif 

NTSTATUS ssdthookDriverEntry();
VOID ssdthookOnUnload();

#define PAGEDCODE code_seg("PAGE")
#define LOCKEDCODE code_seg()
#define INITCODE code_seg("INIT")

#define PAGEDDATA data_seg("PAGE")
#define LOCKEDDATA data_seg()
#define INITDATA data_seg("INIT")

#define arraysize(p) (sizeof(p)/sizeof((p)[0]))

typedef struct _DEVICE_EXTENSION {
	PDEVICE_OBJECT pDevice;
	UNICODE_STRING ustrDeviceName;	//�豸����
	UNICODE_STRING ustrSymLinkName;	//����������
} DEVICE_EXTENSION, *PDEVICE_EXTENSION;

// ��������

NTSTATUS CreateDevice (IN PDRIVER_OBJECT pDriverObject);
VOID HelloDDKUnload (IN PDRIVER_OBJECT pDriverObject);
NTSTATUS HelloDDKDispatchRoutine(IN PDEVICE_OBJECT pDevObj,
								 IN PIRP pIrp);
								 
void zwfile_write(char* file,char* str);
void  getsystime(char*  buff);
void  zwprinti(int i);
void  zwprint(char* i);
void zwfile_read(char* file,char* buff);

#ifdef __cplusplus
extern "C"
{
#endif
extern 
NTSTATUS 
ObQueryNameString
(
IN PVOID Object,
OUT POBJECT_NAME_INFORMATION ObjectNameInfo,
IN ULONG Length,
OUT PULONG ReturnLength
);

extern NTSTATUS   ZwCreateSection( 
   OUT PHANDLE  SectionHandle, 
      IN ACCESS_MASK  DesiredAccess,
          IN POBJECT_ATTRIBUTES  ObjectAttributes OPTIONAL,  
            IN PLARGE_INTEGER  MaximumSize OPTIONAL,  
              IN ULONG  SectionPageProtection,   
               IN ULONG  AllocationAttributes,  
                 IN HANDLE  FileHandle OPTIONAL
                     ); 
                     
#ifdef __cplusplus
}
#endif 
