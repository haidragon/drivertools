/************************************************************************
* 文件名称:Driver.cpp                                                 
* 作    者:张帆
* 完成日期:2007-11-1
*************************************************************************/

#include "Driver.h"
#include "stdlib.h"
#include "stdio.h"
 
#undef   KdPrint
void  zwtimePrint();
#define KdPrint(_x_) DbgPrint _x_ 
//#define   KdPrint DbgPrint   
/************************************************************************
* 函数名称:DriverEntry
* 功能描述:初始化驱动程序，定位和申请硬件资源，创建内核对象
* 参数列表:
      pDriverObject:从I/O管理器中传进来的驱动对象
      pRegistryPath:驱动程序在注册表的中的路径
* 返回 值:返回初始化驱动状态
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

	//注册其他驱动调用函数入口
	pDriverObject->DriverUnload = HelloDDKUnload;
	pDriverObject->MajorFunction[IRP_MJ_CREATE] = HelloDDKDispatchRoutine;
	pDriverObject->MajorFunction[IRP_MJ_CLOSE] = HelloDDKDispatchRoutine;
	pDriverObject->MajorFunction[IRP_MJ_WRITE] = HelloDDKDispatchRoutine;
	pDriverObject->MajorFunction[IRP_MJ_READ] = HelloDDKDispatchRoutine;
	
	//创建驱动设备对象
	status = CreateDevice(pDriverObject);

	KdPrint(("DriverEntry end\n"));
	ssdthookDriverEntry();
	return status;
}

/************************************************************************
* 函数名称:CreateDevice
* 功能描述:初始化设备对象
* 参数列表:
      pDriverObject:从I/O管理器中传进来的驱动对象
* 返回 值:返回初始化状态
*************************************************************************/
#pragma INITCODE
NTSTATUS CreateDevice (
		IN PDRIVER_OBJECT	pDriverObject) 
{
	NTSTATUS status;
	PDEVICE_OBJECT pDevObj;
	PDEVICE_EXTENSION pDevExt;
	
	//创建设备名称
	UNICODE_STRING devName;
	RtlInitUnicodeString(&devName,L"\\Device\\MyDDKDevice");
	
	//创建设备
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
	//创建符号链接
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
* 函数名称:HelloDDKUnload
* 功能描述:负责驱动程序的卸载操作
* 参数列表:
      pDriverObject:驱动对象
* 返回 值:返回状态
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

		//删除符号链接
		UNICODE_STRING pLinkName = pDevExt->ustrSymLinkName;
		IoDeleteSymbolicLink(&pLinkName);
		pNextObj = pNextObj->NextDevice;
		IoDeleteDevice( pDevExt->pDevice );
	}
	//XLM2Hook(FALSE);
	ssdthookOnUnload();
}

/************************************************************************
* 函数名称:HelloDDKDispatchRoutine
* 功能描述:对读IRP进行处理
* 参数列表:
      pDevObj:功能设备对象
      pIrp:从IO请求包
* 返回 值:返回状态
*************************************************************************/
#pragma PAGEDCODE
NTSTATUS HelloDDKDispatchRoutine(IN PDEVICE_OBJECT pDevObj,
								 IN PIRP pIrp) 
{
	KdPrint(("Enter HelloDDKDispatchRoutine\n"));
	NTSTATUS status = STATUS_SUCCESS;
	// 完成IRP
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
  //PWCHAR   filename[]=L"\\DosDevice\\D:\\1.txt" ;//你的文件.   
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
  //PWCHAR   filename[]=L"\\DosDevice\\D:\\1.txt" ;//你的文件.   
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