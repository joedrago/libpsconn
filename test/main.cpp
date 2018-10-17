#include "psconn.h"

#include <stdio.h>
#include <windows.h>

int main(int argc, char * argv[])
{
    while (1) {
        Sleep(1000);

        unsigned int tick = GetTickCount();
        printf("Querying...\n");
        PSConn * psconn = psconnCreate();
        if (psconnConnect(psconn, "172.22.202.92", "123456")) {
            printf("Querying took %d ms.\n", (int)(GetTickCount() - tick));

            PSConnImage * image = psconnGetImage(psconn);
            if (image->width && image->height && image->pixels) {
                printf("Got image: %dx%d, first pixel (%d,%d,%d)\n", image->width, image->height, (int)image->pixels[0], (int)image->pixels[1], (int)image->pixels[2]);
            } else {
                printf("Connected, no image loaded.\n");
            }
        }
        psconnDestroy(psconn);
    }
    return 0;
}
