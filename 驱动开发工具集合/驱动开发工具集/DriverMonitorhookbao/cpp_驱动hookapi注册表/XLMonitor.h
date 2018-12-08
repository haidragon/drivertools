//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
/*
XLMonitor.h (XLMonitor.sys)

create 
modify

*/


#ifndef _XLMonitor_H
#define _XLMonitor_H 1

//
// Define the various device type values. Note that values used by Microsoft
// Corporation are in the range 0-0x7FFF(32767), and 0x8000(32768)-0xFFFF(65535)
// are reserved for use by customers.
//

#define FILE_DEVICE_XLMonitor 0x8000

//
// Macro definition for defining IOCTL and FSCTL function control codes. Note
// that function codes 0-0x7FF(2047) are reserved for Microsoft Corporation,
// and 0x800(2048)-0xFFF(4095) are reserved for customers.
//

#define XLMonitor_IOCTL_BASE 0x800


//
// The device driver IOCTLs
//

#define CTL_CODE_XLMonitor(i) CTL_CODE(FILE_DEVICE_XLMonitor, XLMonitor_IOCTL_BASE+i, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_XLMonitor_HELLO CTL_CODE_XLMonitor(0)
#define IOCTL_XLMonitor_TEST CTL_CODE_XLMonitor(1)

//
// Name that Win32 front end will use to open the XLMonitor device
//

#define XLMonitor_WIN32_DEVICE_NAME_A "\\\\.\\XLMonitor"
#define XLMonitor_WIN32_DEVICE_NAME_W L"\\\\.\\XLMonitor"
#define XLMonitor_DEVICE_NAME_A    "\\Device\\XLMonitor"
#define XLMonitor_DEVICE_NAME_W    L"\\Device\\XLMonitor"
#define XLMonitor_DOS_DEVICE_NAME_A   "\\DosDevices\\XLMonitor"
#define XLMonitor_DOS_DEVICE_NAME_W   L"\\DosDevices\\XLMonitor"

#ifdef _UNICODE
#define XLMonitor_WIN32_DEVICE_NAME XLMonitor_WIN32_DEVICE_NAME_W
#define XLMonitor_DEVICE_NAME   XLMonitor_DEVICE_NAME_W
#define XLMonitor_DOS_DEVICE_NAME XLMonitor_DOS_DEVICE_NAME_W
#else
#define XLMonitor_WIN32_DEVICE_NAME XLMonitor_WIN32_DEVICE_NAME_A
#define XLMonitor_DEVICE_NAME   XLMonitor_DEVICE_NAME_A
#define XLMonitor_DOS_DEVICE_NAME XLMonitor_DOS_DEVICE_NAME_A
#endif
#endif

 