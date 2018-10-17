cmake_minimum_required(VERSION 2.8)
project(libpsconn)

include_directories(ext/jpeg)
add_library(jpeg STATIC
    ext/jpeg/cdjpeg.c
    ext/jpeg/jaricom.c
    ext/jpeg/jcapimin.c
    ext/jpeg/jcapistd.c
    ext/jpeg/jcarith.c
    ext/jpeg/jccoefct.c
    ext/jpeg/jccolor.c
    ext/jpeg/jcdctmgr.c
    ext/jpeg/jchuff.c
    ext/jpeg/jcinit.c
    ext/jpeg/jcmainct.c
    ext/jpeg/jcmarker.c
    ext/jpeg/jcmaster.c
    ext/jpeg/jcomapi.c
    ext/jpeg/jcparam.c
    ext/jpeg/jcprepct.c
    ext/jpeg/jcsample.c
    ext/jpeg/jctrans.c
    ext/jpeg/jdapimin.c
    ext/jpeg/jdapistd.c
    ext/jpeg/jdarith.c
    ext/jpeg/jdatadst.c
    ext/jpeg/jdatasrc.c
    ext/jpeg/jdcoefct.c
    ext/jpeg/jdcolor.c
    ext/jpeg/jddctmgr.c
    ext/jpeg/jdhuff.c
    ext/jpeg/jdinput.c
    ext/jpeg/jdmainct.c
    ext/jpeg/jdmarker.c
    ext/jpeg/jdmaster.c
    ext/jpeg/jdmerge.c
    ext/jpeg/jdpostct.c
    ext/jpeg/jdsample.c
    ext/jpeg/jdtrans.c
    ext/jpeg/jerror.c
    ext/jpeg/jfdctflt.c
    ext/jpeg/jfdctfst.c
    ext/jpeg/jfdctint.c
    ext/jpeg/jidctflt.c
    ext/jpeg/jidctfst.c
    ext/jpeg/jidctint.c
    ext/jpeg/jmemmgr.c
    ext/jpeg/jmemnobs.c
    ext/jpeg/jquant1.c
    ext/jpeg/jquant2.c
    ext/jpeg/jutils.c
    ext/jpeg/rdbmp.c
    ext/jpeg/rdcolmap.c
    ext/jpeg/rdgif.c
    ext/jpeg/rdppm.c
    ext/jpeg/rdrle.c
    ext/jpeg/rdswitch.c
    ext/jpeg/rdtarga.c
    ext/jpeg/transupp.c
    ext/jpeg/wrbmp.c
    ext/jpeg/wrgif.c
    ext/jpeg/wrjpgcom.c
    ext/jpeg/wrppm.c
    ext/jpeg/wrrle.c
    ext/jpeg/wrtarga.c
)

set(PSCONN_LIB_NAME psconn)
include_directories(
    src
    ext/photoshopapi
)
set(PSCONN_SRCS
    src/psconn.h
    src/psconn.cpp
    src/psconn_jpg.cpp
    ext/photoshopapi/PSCryptor.cpp
    ext/photoshopapi/PBKeyDerive.cpp
)
add_library(${PSCONN_LIB_NAME} STATIC ${PSCONN_SRCS})

option(PSCONN_BUILD_TEST_APP "Build test app for libpsconn" OFF)
if(PSCONN_BUILD_TEST_APP)
    add_executable(psconn_test test/main.cpp)
    target_link_libraries(psconn_test ${PSCONN_LIB_NAME} jpeg)
endif(PSCONN_BUILD_TEST_APP)
