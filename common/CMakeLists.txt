################################
# COMMON
################################
set(SRC_COMMON_PROC_DIR ${SRC_COMMON_DIR}/processors)
file(GLOB SRC_COMMON_PROC_H ${SRC_COMMON_PROC_DIR}/*.h)
file(GLOB SRC_COMMON_PROC ${SRC_COMMON_PROC_DIR}/*.c)

set(SRC_COMMON_CDC_DIR ${SRC_COMMON_DIR}/cdc)
file(GLOB SRC_COMMON_CDC_H ${SRC_COMMON_CDC_DIR}/*.h)
file(GLOB SRC_COMMON_CDC ${SRC_COMMON_CDC_DIR}/*.c)
add_subdirectory(cdc)

set(SRC_COMMON_INDEX_DIR ${SRC_COMMON_DIR}/index)
add_subdirectory(index)
