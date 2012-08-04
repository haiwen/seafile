/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#ifndef STDAFX_H_
#define STDAFX_H_

// 如果必须将位于下面指定平台之前的平台作为目标，请修改下列定义。
// 有关不同平台对应值的最新信息，请参考 MSDN。
#ifndef WINVER              // 允许使用特定于 Windows XP 或更高版本的功能。
#define WINVER 0x0501       // 将此值更改为相应的值，以适用于 Windows 的其他版本。
#endif

#ifndef _WIN32_WINNT        // 允许使用特定于 Windows XP 或更高版本的功能。
#define _WIN32_WINNT 0x0501 // 将此值更改为相应的值，以适用于 Windows 的其他版本。
#endif                      

#ifndef _WIN32_WINDOWS      // 允许使用特定于 Windows 98 或更高版本的功能。
#define _WIN32_WINDOWS 0x0410 // 将此值更改为适当的值，以指定将 Windows Me 或更高版本作为目标。
#endif

#ifndef _WIN32_IE           // 允许使用特定于 IE 6.0 或更高版本的功能。
#define _WIN32_IE 0x0600    // 将此值更改为相应的值，以适用于 IE 的其他版本。
#endif

#define WIN32_LEAN_AND_MEAN     // 从 Windows 头中排除极少使用的资料
// Windows 头文件:
#include <windows.h>
#include <winsock2.h>

// C 运行时头文件
#include <stdlib.h>
#include <malloc.h>
#include <memory.h>
#include <tchar.h>


#endif
