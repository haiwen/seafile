#pragma once

typedef void *CBPWrapperExceptionHandler;
#ifdef __cplusplus
extern "C"
{
#endif
    CBPWrapperExceptionHandler newCBPWrapperExceptionHandler(const char *dump_dir);

#ifdef __cplusplus
}
#endif