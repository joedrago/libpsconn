#include "psconn.h"

#include <stdio.h>
#include "jpeglib.h"

#include <stdlib.h>
#include <string.h>
#include <setjmp.h>

struct my_error_mgr
{
    struct jpeg_error_mgr pub;
    jmp_buf setjmp_buffer;
};
typedef struct my_error_mgr * my_error_ptr;
static void my_error_exit(j_common_ptr cinfo)
{
    my_error_ptr myerr = (my_error_ptr)cinfo->err;
    (*cinfo->err->output_message)(cinfo);
    longjmp(myerr->setjmp_buffer, 1);
}

PSConnBool psconnDecodeJPEG(uint8_t * rawJPEG, int rawJPEGLen, struct PSConnImage * outImage)
{
    struct my_error_mgr jerr;
    struct jpeg_decompress_struct cinfo;
    JSAMPARRAY buffer;
    int row_stride;
    int row;

    cinfo.err = jpeg_std_error(&jerr.pub);
    jerr.pub.error_exit = my_error_exit;
    if (setjmp(jerr.setjmp_buffer)) {
        jpeg_destroy_decompress(&cinfo);
        return PSConnFalse;
    }

    jpeg_create_decompress(&cinfo);
    jpeg_mem_src(&cinfo, rawJPEG, rawJPEGLen);
    jpeg_read_header(&cinfo, TRUE);
    jpeg_start_decompress(&cinfo);

    row_stride = cinfo.output_width * cinfo.output_components;
    buffer = (*cinfo.mem->alloc_sarray)((j_common_ptr) & cinfo, JPOOL_IMAGE, row_stride, 1);

    if ((outImage->width != cinfo.output_width) || (outImage->height != cinfo.output_height)) {
        outImage->width = cinfo.output_width;
        outImage->height = cinfo.output_height;
        if (outImage->pixels) {
            free(outImage->pixels);
        }
        if (outImage->width && outImage->height) {
            outImage->pixels = (uint8_t *)malloc(3 * outImage->width * outImage->height);
        }
    }
    row = 0;
    while (cinfo.output_scanline < cinfo.output_height) {
        jpeg_read_scanlines(&cinfo, buffer, 1);
        uint8_t * pixelRow = &outImage->pixels[row * 3 * outImage->width];
        memcpy(pixelRow, buffer[0], 3 * outImage->width);
        ++row;
    }
    jpeg_finish_decompress(&cinfo);
    jpeg_destroy_decompress(&cinfo);
    return PSConnTrue;
}
