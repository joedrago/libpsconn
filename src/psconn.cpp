#define _WINSOCK_DEPRECATED_NO_WARNINGS

// Let me be naughty and use strdup(), thx
#pragma warning( disable : 4996 )

#include "psconn.h"

#include "PSCryptorAPI.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#pragma comment(lib,"wsock32.lib")
#include <winsock2.h>

// #define PSCONN_DEBUG_PRINTING 1
#ifdef PSCONN_DEBUG_PRINTING
#define pdprintf printf
#else
#define pdprintf(...)
#endif

#define PHOTOSHOP_DEFAULT_PORT 49494

struct PSUnencryptedPacketHeader
{
    int32_t length;
    int32_t status;
};

struct PSResponseProlog
{
    int32_t version;
    int32_t transactionID;
    int32_t contentType;
};

struct PSConn
{
    struct PSConnImage image;
    SOCKET s;
    PSCryptorRef cryptor;
    int32_t nextTransactionID;
};

static void psconnClose(struct PSConn * psconn)
{
    if (psconn->s != INVALID_SOCKET) {
        pdprintf("  psconnClose %p\n", psconn);
        closesocket(psconn->s);
        psconn->s = INVALID_SOCKET;
    }
    if (psconn->cryptor) {
        DestroyPSCryptor(psconn->cryptor);
        psconn->cryptor = NULL;
    }
}

struct PSConn * psconnCreate()
{
    struct PSConn * psconn = (struct PSConn *)calloc(1, sizeof(PSConn));
    psconn->s = INVALID_SOCKET;

    pdprintf("psconnCreate %p\n", psconn);

    WORD wVersionRequested = MAKEWORD(2, 2);
    WSADATA wsaData;
    int err;

    err = WSAStartup(wVersionRequested, &wsaData);
    if (err != 0) {
        pdprintf("WSAStartup failed with error: %d\n", err);
        return NULL;
    }
    return psconn;
}

void psconnDestroy(struct PSConn * psconn)
{
    pdprintf("psconnDestroy %p\n", psconn);

    psconnClose(psconn);
    if (psconn->image.pixels) {
        free(psconn->image.pixels);
        psconn->image.pixels = NULL;
    }
    free(psconn);

    WSACleanup();
}

static PSConnBool psconnProcessDecryptedPayload(struct PSConn * psconn, uint8_t * payload, int payloadLen)
{
    PSResponseProlog prolog;
    memcpy(&prolog, payload, sizeof(prolog));
    prolog.version = ntohl(prolog.version);
    prolog.transactionID = ntohl(prolog.transactionID);
    prolog.contentType = ntohl(prolog.contentType);
    if (prolog.contentType == 3) {
        uint8_t * front = payload + sizeof(prolog);
        uint8_t imageType = 0;
        memcpy(&imageType, front, 1);
        front += 1;
        if (imageType == 1) { // JPEG
            uint8_t * rawJPEG = front;
            int rawJPEGLen = payloadLen - sizeof(prolog) - 1;
            return psconnDecodeJPEG(rawJPEG, rawJPEGLen, &psconn->image);
        } else if (imageType == 2) { // PixMap
            struct PixmapHeader
            {
                int32_t width;
                int32_t height;
                int32_t rowBytes;
                int8_t colorMode;
                int8_t channelCount;
                int8_t bitsPerChannel;
                int8_t ignored;
            };
            PixmapHeader pixmapHeader;
            memcpy(&pixmapHeader, front, sizeof(pixmapHeader));
            front += sizeof(pixmapHeader) - 1; // -1 to kill ignored
            pixmapHeader.width = ntohl(pixmapHeader.width);
            pixmapHeader.height = ntohl(pixmapHeader.height);
            pixmapHeader.rowBytes = ntohl(pixmapHeader.rowBytes);
            if ((pixmapHeader.colorMode == 1) // RGB
                && (pixmapHeader.channelCount == 3)
                && (pixmapHeader.bitsPerChannel == 8)
                )
            {
                if ((psconn->image.width != pixmapHeader.width) || (psconn->image.height != pixmapHeader.height)) {
                    psconn->image.width = pixmapHeader.width;
                    psconn->image.height = pixmapHeader.height;
                    if (psconn->image.pixels) {
                        free(psconn->image.pixels);
                    }
                    psconn->image.pixels = (uint8_t *)malloc(3 * psconn->image.width * psconn->image.height);
                }
                memcpy(psconn->image.pixels, front, 3 * psconn->image.width * psconn->image.height);
                return PSConnTrue;
            }
        }
    }

    return PSConnFalse;
}

static PSConnBool psconnSendRequest(struct PSConn * psconn, const char * js)
{
    int dataType = 2; // JavaScript
    size_t plainTextLength = strlen(js) + 12;
    size_t encryptedLength = CryptorGetEncryptedLength(plainTextLength);

    int swabbed_temp;
    uint8_t * tempBuffer = (uint8_t *)malloc(encryptedLength);

    // protocol version, 32 bit unsigned integer
    swabbed_temp = htonl(1);
    memcpy(tempBuffer + 0, (const void *)&swabbed_temp, 4);

    // transaction id, 32 bit unsigned integer
    ++psconn->nextTransactionID;
    swabbed_temp = htonl(psconn->nextTransactionID);
    memcpy(tempBuffer + 4, (const void *)&swabbed_temp, 4);

    // content type, 32 bit unsigned integer
    swabbed_temp = htonl(dataType);
    memcpy(tempBuffer + 8, (const void *)&swabbed_temp, 4);

    // and the data passed in
    memcpy(tempBuffer + 12, js, strlen(js));

    // now encrypt the message packet
    EncryptDecrypt(psconn->cryptor, true, tempBuffer, plainTextLength, tempBuffer, encryptedLength, &encryptedLength);

    PSUnencryptedPacketHeader header;
    memset(&header, 0, sizeof(header));
    header.length = htonl(4 + encryptedLength);

    PSConnBool result = PSConnFalse;

    int bytesSent;
    bytesSent = send(psconn->s, (const char *)&header, sizeof(header), 0);
    if (bytesSent == sizeof(header)) {
        bytesSent = send(psconn->s, (const char *)tempBuffer, encryptedLength, 0);
        if (bytesSent == encryptedLength) {
            int bytesRead;
            int responseLen = 0;
            bytesRead = recv(psconn->s, (char *)&responseLen, 4, 0);
            if (bytesRead == 4) {
                responseLen = ntohl(responseLen);
                uint8_t * responseBytes = (uint8_t *)malloc(responseLen);
                uint8_t * front = responseBytes;
                int remaining = responseLen;
                while (remaining > 0) {
                    bytesRead = recv(psconn->s, (char *)front, remaining, 0);
                    if (bytesRead == SOCKET_ERROR) {
                        break;
                    }
                    front += bytesRead;
                    remaining -= bytesRead;
                }
                if (remaining == 0) {
                    pdprintf("  Received %d byte response\n", responseLen);
                    int status = 0;
                    memcpy(&status, responseBytes, 4);
                    status = ntohl(status);
                    if (status == 0) {
                        size_t decryptedBytes = 0;
                        EncryptDecrypt(psconn->cryptor, false, responseBytes + 4, responseLen - 4, responseBytes, responseLen, &decryptedBytes);
                        pdprintf("  Decrypted %d bytes\n", (int)decryptedBytes);

                        result = psconnProcessDecryptedPayload(psconn, responseBytes, decryptedBytes);
                    } else {
                        pdprintf("  Failed to decrypt response\n");
                    }
                } else {
                    pdprintf("  Failed to download full response\n");
                }
            } else {
                pdprintf("  Failed to read response length\n");
            }
        }
    }

    free(tempBuffer);
    return result;
}

PSConnBool psconnUpdateImage(struct PSConn * psconn)
{
    if (psconn->s == INVALID_SOCKET) {
        return PSConnFalse;
    }

    char buffer[1024];
    sprintf(buffer, "var idNS = stringIDToTypeID( \"sendDocumentThumbnailToNetworkClient\" );"
        "var desc1 = new ActionDescriptor();"
        "desc1.putInteger( stringIDToTypeID( \"width\" ), %d );"
        "desc1.putInteger( stringIDToTypeID( \"height\" ), %d );"
        "desc1.putInteger( stringIDToTypeID( \"format\" ), %d );"
        "desc1.putBoolean( stringIDToTypeID( \"thread\" ), true );"
        "desc1.putBoolean( stringIDToTypeID( \"convertToWorkingRGBProfile\" ), false );"
        "desc1.putString( stringIDToTypeID( \"useICCProfile\" ), \"BT.2020 G2.2 10000nits\");"
        "desc1.putBoolean( stringIDToTypeID( \"allowDither\" ), false ); "
        "desc1.putBoolean( stringIDToTypeID( \"useColorSettingsDither\" ), false );"
        "executeAction( idNS, desc1, DialogModes.NO );",
        3840, 2160, // TODO: not this
        2           // 1 for JPEG, 2 for Pixmap
        );

    return psconnSendRequest(psconn, buffer);
}

struct PSConnImage * psconnGetImage(struct PSConn * psconn)
{
    return &psconn->image;
}

PSConnBool psconnConnect(struct PSConn * psconn, const char * host, const char * password)
{
    pdprintf("psconnConnect %p\n", psconn);
    psconnClose(psconn);

    psconn->s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (psconn->s == INVALID_SOCKET) {
        pdprintf("  socket function failed with error: %ld\n", WSAGetLastError());
        return PSConnFalse;
    }

    sockaddr_in clientService;
    clientService.sin_family = AF_INET;
    clientService.sin_addr.s_addr = inet_addr(host); // TODO: Support hostnames
    clientService.sin_port = htons(PHOTOSHOP_DEFAULT_PORT);

    int iResult = connect(psconn->s, (SOCKADDR *)&clientService, sizeof(clientService));
    if (iResult == SOCKET_ERROR) {
        pdprintf("  connect function failed with error: %ld\n", WSAGetLastError());
        psconnClose(psconn);
        WSACleanup();
        return PSConnFalse;
    }

    psconn->cryptor = CreatePSCryptor(password);

    pdprintf("psconnConnect %p success!\n", psconn);
    psconnUpdateImage(psconn);
    return PSConnTrue;
}
