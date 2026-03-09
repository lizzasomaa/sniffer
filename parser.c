#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include "process.h"
#include "live_process.h"

int main(int argc, char* argv[]) {
    char *path = NULL;
    char *interface = NULL;

    for (int i = 1; i < argc; i++) { 
        if (strcmp(argv[i], "-r") == 0) {
            if (i + 1 < argc) {
                path = argv[i + 1];
                i++;
            } else {
                printf("Error: -r requires a path\n");
                return 1;
            }
        }
        else if (strcmp(argv[i], "-i") == 0) {
            if (i + 1 < argc) {
                interface = argv[i + 1];
                i++;
            } else {
                printf("Error: -i requires an interface name\n");
                return 1;
            }
        }
        else {
            printf("Unknown argument: %s\n", argv[i]);
            return 1;
        }
    }

    if ((path == NULL && interface == NULL) || (path != NULL && interface != NULL)) {
        printf("Use either -r <file/dir> OR -i <interface>\n");
        return 1;
    }

    if (interface != NULL) {
        process_live_interface(interface);
        return 0;
    }

    struct stat path_stat;
    if (stat(path, &path_stat) != 0) {
        perror("stat failed");
        return 1;
    }

    if (S_ISREG(path_stat.st_mode)) {
        process_pcap_file(path);
    }
    else if (S_ISDIR(path_stat.st_mode)) {
        process_directory(path);
    }
    else {
        printf("Unsupported file type\n");
        return 1;
    }

    return 0;
}
