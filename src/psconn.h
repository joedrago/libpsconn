#ifndef PSCONN_H
#define PSCONN_H

#include <stdint.h>

typedef int PSConnBool;
#define PSConnFalse 0
#define PSConnTrue 1

struct PSConn;

typedef struct PSConnImage
{
    int width;
    int height;
    uint8_t * pixels;
} PSConnImage;

struct PSConn * psconnCreate();
void psconnDestroy(struct PSConn * psconn);
PSConnBool psconnConnect(struct PSConn * psconn, const char * host, const char * password);
PSConnBool psconnUpdateImage(struct PSConn * psconn);
struct PSConnImage * psconnGetImage(struct PSConn * psconn);

// internal functions
PSConnBool psconnDecodeJPEG(uint8_t * rawJPEG, int rawJPEGLen, struct PSConnImage * outImage);

#endif
