/************************************************************************
* �ļ�����:Driver.cpp                                                 
* ��    ��:�ŷ�
* �������:2007-11-1
*************************************************************************/

#include "Driver.h"
#include "stdlib.h"
#include "stdio.h"
 
#undef   KdPrint
void  zwtimePrint();
#define KdPrint(_x_) DbgPrint _x_ 
//#define   KdPrint DbgPrint   
/************************************************************************
* ��������:DriverEntry
* ��������:��ʼ���������򣬶�λ������Ӳ����Դ�������ں˶���
* �����б�:
      pDriverObject:��I/O�������д���������������
      pRegistryPath:����������ע�����е�·��
* ���� ֵ:���س�ʼ������״̬
*************************************************************************/
#pragma INITCODE
extern "C" NTSTATUS DriverEntry (
			IN PDRIVER_OBJECT pDriverObject,
			IN PUNICODE_STRING pRegistryPath	) 
{
	NTSTATUS status;
	KdPrint(("Enter DriverEntry\n"));
		KdPrint(("Enter DriverEntry\n"));

	KdPrint(("Enter DriverEntry\n"));

	KdPrint(("Enter DriverEntry\n"));
zwtimePrint();
	zwfile_write(0,"ddddddd");

	//ע�������������ú������
	pDriverObject->DriverUnload = HelloDDKUnload;
	pDriverObject->MajorFunction[IRP_MJ_CREATE] = HelloDDKDispatchRoutine;
	pDriverObject->MajorFunction[IRP_MJ_CLOSE] = HelloDDKDispatchRoutine;
	pDriverObject->MajorFunction[IRP_MJ_WRITE] = HelloDDKDispatchRoutine;
	pDriverObject->MajorFunction[IRP_MJ_READ] = HelloDDKDispatchRoutine;
	
	//���������豸����
	status = CreateDevice(pDriverObject);

	KdPrint(("DriverEntry end\n"));
	ssdthookDriverEntry();
	return status;
}

/************************************************************************
* ��������:CreateDevice
* ��������:��ʼ���豸����
* �����б�:
      pDriverObject:��I/O�������д���������������
* ���� ֵ:���س�ʼ��״̬
*************************************************************************/
#pragma INITCODE
NTSTATUS CreateDevice (
		IN PDRIVER_OBJECT	pDriverObject) 
{
	NTSTATUS status;
	PDEVICE_OBJECT pDevObj;
	PDEVICE_EXTENSION pDevExt;
	
	//�����豸����
	UNICODE_STRING devName;
	RtlInitUnicodeString(&devName,L"\\Device\\MyDDKDevice");
	
	//�����豸
	status = IoCreateDevice( pDriverObject,
						sizeof(DEVICE_EXTENSION),
						&(UNICODE_STRING)devName,
						FILE_DEVICE_UNKNOWN,
						0, TRUE,
						&pDevObj );
	if (!NT_SUCCESS(status))
		return status;

	pDevObj->Flags |= DO_BUFFERED_IO;
	pDevExt = (PDEVICE_EXTENSION)pDevObj->DeviceExtension;
	pDevExt->pDevice = pDevObj;
	pDevExt->ustrDeviceName = devName;
	//������������
	UNICODE_STRING symLinkName;
	RtlInitUnicodeString(&symLinkName,L"\\??\\HelloDDK");
	pDevExt->ustrSymLinkName = symLinkName;
	status = IoCreateSymbolicLink( &symLinkName,&devName );
	if (!NT_SUCCESS(status)) 
	{
		IoDeleteDevice( pDevObj );
		return status;
	}
	return STATUS_SUCCESS;
}

/************************************************************************
* ��������:HelloDDKUnload
* ��������:�������������ж�ز���
* �����б�:
      pDriverObject:��������
* ���� ֵ:����״̬
*************************************************************************/
#pragma PAGEDCODE
VOID HelloDDKUnload (IN PDRIVER_OBJECT pDriverObject) 
{
	PDEVICE_OBJECT	pNextObj;
	KdPrint(("Enter DriverUnload\n"));
	pNextObj = pDriverObject->DeviceObject;
	while (pNextObj != NULL) 
	{
		PDEVICE_EXTENSION pDevExt = (PDEVICE_EXTENSION)
			pNextObj->DeviceExtension;

		//ɾ����������
		UNICODE_STRING pLinkName = pDevExt->ustrSymLinkName;
		IoDeleteSymbolicLink(&pLinkName);
		pNextObj = pNextObj->NextDevice;
		IoDeleteDevice( pDevExt->pDevice );
	}
	//XLM2Hook(FALSE);
	ssdthookOnUnload();
}

/************************************************************************
* ��������:HelloDDKDispatchRoutine
* ��������:�Զ�IRP���д���
* �����б�:
      pDevObj:�����豸����
      pIrp:��IO�����
* ���� ֵ:����״̬
*************************************************************************/
#pragma PAGEDCODE
NTSTATUS HelloDDKDispatchRoutine(IN PDEVICE_OBJECT pDevObj,
								 IN PIRP pIrp) 
{
	KdPrint(("Enter HelloDDKDispatchRoutine\n"));
	NTSTATUS status = STATUS_SUCCESS;
	// ���IRP
	pIrp->IoStatus.Status = status;
	pIrp->IoStatus.Information = 0;	// bytes xfered
	IoCompleteRequest( pIrp, IO_NO_INCREMENT );
	zwfile_write(0,"hello is a test");
	KdPrint(("Leave HelloDDKDispatchRoutine\n"));
	return status;
}
#undef   KdPrint    
void  zwtimePrint(){	
   LARGE_INTEGER    SysTime, LocalTime; 
   TIME_FIELDS      TimeFields; 

   KeQuerySystemTime(&SysTime); 
   ExSystemTimeToLocalTime(&SysTime, &LocalTime); 
   RtlTimeToTimeFields(&LocalTime, &TimeFields); 
   DbgPrint("SystemTime: %d-%d-%d, %d:%d:%d\n", 
     TimeFields.Year, TimeFields.Month, TimeFields.Day, 
     TimeFields.Hour, TimeFields.Minute, TimeFields.Second 
     );
}
void  getsystime(char*  buff);

void zwtimewrite(char* f)
{
	char  buff[1000];
	getsystime(  buff);
zwfile_write(f,buff);
	
}
void  zwprinti(int i)
{
	char buf[102];
	sprintf(buf,"%d(0x%x)", i,i);
	 DbgPrint(buf);
	 zwfile_write(0,buf);
}

void  zwprint(char* i)
{
	zwtimePrint();
	DbgPrint("%s", i);
	zwfile_write(0,i);
	
}
void  getsystime(char*  buff)
{
	
  LARGE_INTEGER    SysTime, LocalTime; 
   TIME_FIELDS      TimeFields; 
   KeQuerySystemTime(&SysTime); 
   ExSystemTimeToLocalTime(&SysTime, &LocalTime); 
   RtlTimeToTimeFields(&LocalTime, &TimeFields); 
	 sprintf(buff,"[%d-%d-%d %d:%d:%d]", TimeFields.Year, TimeFields.Month, TimeFields.Day, TimeFields.Hour, TimeFields.Minute, TimeFields.Second);

}
#define print    DbgPrint

void zwfile_read(char* file,char* buff)
{
	NTSTATUS   status;   
  OBJECT_ATTRIBUTES   oa;   
  UNICODE_STRING   usname;   
  HANDLE   handle;   
  IO_STATUS_BLOCK   iostatus;   
  //PWCHAR   filename[]=L"\\DosDevice\\D:\\1.txt" ;//����ļ�.   
  PVOID   buffer;
  ULONG   nbytes;   
  int len=0;
  //char  buf[1000];
  RtlInitUnicodeString(&usname,   L"\\DosDevices\\D:\\2.txt"); 
  //RtlInitUnicodeString(&uniDeviceName ,L"\\DosDevices\\C:\\");
   // RtlInitUnicodeString( &usname, L"\\\\??\\C:\\1.txt"); 
  
 // InitializeObjectAttributes(&oa,   &usname,   OBJ_CASE_INSENSITIVE   |   OBJ_KERNEL_HANDLE,   NULL,   NULL);   
   InitializeObjectAttributes(&oa,   &usname,   OBJ_CASE_INSENSITIVE |OBJ_KERNEL_HANDLE   ,   NULL,   NULL);   
 
  //status   =   ZwCreateFile(&handle,   GENERIC_WRITE,   &oa,   &iostatus,   NULL,     FILE_ATTRIBUTE_NORMAL,   0,   FILE_OVERWRITE_IF,   FILE_SYNCHRONOUS_IO_NONALERT,   NULL,   0);   
  //  status   =   ZwCreateFile(&handle,   GENERIC_ALL,   &oa,   &iostatus,   NULL,     FILE_ATTRIBUTE_NORMAL,   0,   FILE_OPEN,   FILE_SYNCHRONOUS_IO_NONALERT,   NULL,   0);    
  status   =   ZwCreateFile(&handle,   FILE_READ_DATA|SYNCHRONIZE,   &oa,   &iostatus,   NULL,     FILE_ATTRIBUTE_NORMAL,   0,   FILE_OPEN_IF,   FILE_SYNCHRONOUS_IO_NONALERT,   NULL,   0);    
 zwprinti((int)status);
 zwprinti((int)handle);
  //zwprinti((int)status);
  //zwprinti((int)handle);
  
  //getsystime(buf);
 // strcat(buf,str);
 // strcat(buf,"\n");
  status = ZwReadFile(handle,   NULL,   NULL,   NULL,   &iostatus,   buff,   100,   NULL,   NULL); 	
  len=iostatus.Information;
  buff[len]=0;
   if (status==STATUS_END_OF_FILE){
   	zwprint("STATUS_END_OF_FILE");   	
  }
  //status = ZwWriteFile(handle,   NULL,   NULL,   NULL,   &iostatus,   "\n",  1,   NULL,   NULL); 	
  //zwprinti((int)status);
  ZwClose(handle);	
  //zwprinti((int)status);
  zwprint("len =");
  zwprinti((int)len);
  zwprint(buff);
}
void zwfile_write(char* file,char* str)
{
	
	NTSTATUS   status;   
  OBJECT_ATTRIBUTES   oa;   
  UNICODE_STRING   usname;   
  HANDLE   handle;   
  IO_STATUS_BLOCK   iostatus;   
  //PWCHAR   filename[]=L"\\DosDevice\\D:\\1.txt" ;//����ļ�.   
  PVOID   buffer;
  ULONG   nbytes;   
  char  buf[1000];

  RtlInitUnicodeString(&usname,   L"\\DosDevices\\D:\\1.txt"); 
  //RtlInitUnicodeString(&uniDeviceName ,L"\\DosDevices\\C:\\");
   // RtlInitUnicodeString( &usname, L"\\\\??\\C:\\1.txt"); 
  
 // InitializeObjectAttributes(&oa,   &usname,   OBJ_CASE_INSENSITIVE   |   OBJ_KERNEL_HANDLE,   NULL,   NULL);   
   InitializeObjectAttributes(&oa,   &usname,   OBJ_CASE_INSENSITIVE   ,   NULL,   NULL);   
 
  //status   =   ZwCreateFile(&handle,   GENERIC_WRITE,   &oa,   &iostatus,   NULL,     FILE_ATTRIBUTE_NORMAL,   0,   FILE_OVERWRITE_IF,   FILE_SYNCHRONOUS_IO_NONALERT,   NULL,   0);   
  //  status   =   ZwCreateFile(&handle,   GENERIC_ALL,   &oa,   &iostatus,   NULL,     FILE_ATTRIBUTE_NORMAL,   0,   FILE_OPEN,   FILE_SYNCHRONOUS_IO_NONALERT,   NULL,   0);    
  status   =   ZwCreateFile(&handle,   GENERIC_READ|FILE_APPEND_DATA,   &oa,   &iostatus,   NULL,     FILE_ATTRIBUTE_NORMAL,   0,   FILE_OPEN_IF,   FILE_SYNCHRONOUS_IO_NONALERT,   NULL,   0);    
 
  //zwprinti((int)status);
  //zwprinti((int)handle);
  
  getsystime(buf);
  strcat(buf,str);
  strcat(buf,"\n");
  status = ZwWriteFile(handle,   NULL,   NULL,   NULL,   &iostatus,   buf,   strlen(buf),   NULL,   NULL); 	
  //status = ZwWriteFile(handle,   NULL,   NULL,   NULL,   &iostatus,   "\n",  1,   NULL,   NULL); 	
  //zwprinti((int)status);
  ZwClose(handle);
	/*
	 ntstatus = ZwReadFile(handle, NULL, NULL, NULL, &ioStatusBlock,
                              buffer, BUFFER_SIZE, &byteOffset, NULL);
                              */
}