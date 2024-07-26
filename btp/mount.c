#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <stdarg.h>
#include <mntent.h>

#define OPTION_STR "t:a" 

/* All the functions starting with "x" call bb_error_msg_and_die() if they
 * fail, so callers never need to check for errors.  If it returned, it
 * succeeded. */
void bb_die_memory_exhausted(void){
    perror("xmalloc");
    exit(1);
}

// Die if we can't allocate size bytes of memory.
void* xmalloc(size_t size)
{
	void *ptr = malloc(size);
	if (ptr == NULL && size != 0)
		bb_die_memory_exhausted();
	return ptr;
}

// Die if we can't copy a string to freshly allocated memory.
char* xstrdup(const char *s)
{
	char *t;

	if (s == NULL)
		return NULL;

	t = strdup(s);

	if (t == NULL)
		bb_die_memory_exhausted();

	return t;
}

// Die if we can't allocate and zero size bytes of memory.
void* xzalloc(size_t size)
{
	void *ptr = xmalloc(size);
	memset(ptr, 0, size);
	return ptr;
}

char* xasprintf(const char *format, ...)
{
	va_list p;
	int r;
	char *string_ptr;

	va_start(p, format);
	r = vasprintf(&string_ptr, format, p);
	va_end(p);

	if (r < 0)
		bb_die_memory_exhausted();
	return string_ptr;
}

// Append mount options to string
static void append_mount_options(char **oldopts, const char *newopts)
{
	if (*oldopts && **oldopts) {
		// Do not insert options which are already there
		while (newopts[0]) {
			char *p;
			int len;

			len = strchrnul(newopts, ',') - newopts;
			p = *oldopts;
			while (1) {
				if (!strncmp(p, newopts, len)
				 && (p[len] == ',' || p[len] == '\0'))
					goto skip;
				p = strchr(p,',');
				if (!p) break;
				p++;
			}
			p = xasprintf("%s,%.*s", *oldopts, len, newopts);
			free(*oldopts);
			*oldopts = p;
 skip:
			newopts += len;
			while (*newopts == ',') newopts++;
		}
	} else {
		free(*oldopts);
		*oldopts = xstrdup(newopts);
	}
}

int main(int argc, char *argv[]) {
    char *cmdopts = xzalloc(1);
    unsigned opt;
    const char *fstabname = "/etc/fstab"; // for -a 
    FILE *fstab;
    int i, j;

    if (argc == 1) {
        printf("Usage: %s [OPTION]... DEVICE NODE\n",argv[0]);
        printf("Mount a file system.\n");
        printf("\n");
        printf("  -a               modify all filesystems listed in /etc/fstab\n");
        printf("  -t               filesystem type\n");
    }

    // for (i = 1; i < argc; i++) {
    //     printf("Argument %d: %s\n", i, argv[i]);
    // }

    // Parse long options, like --bind and --move.  Note that -o option
	// and --option are synonymous.  Yes, this means --remount,rw works.
	for (i = j = 1; argv[i]; i++) {
		if (argv[i][0] == '-' && argv[i][1] == '-')
			append_mount_options(&cmdopts, argv[i] + 2);
		else
			argv[j++] = argv[i];
	}
	argv[j] = NULL;



    while ((opt = getopt(argc, argv, OPTION_STR)) != -1) {
        switch (opt) {
            case 'a':
                fstab = setmntent(fstabname, "r");
                if (!fstab)
                    fprintf(stderr,"can't read '%s'", fstabname);
                struct mntent* mnt;
                // Iteratively read entries in the mount table.
                while ((mnt = getmntent(fstab)) != NULL) {
                    // mount proc filesystem
                    if (mount(mnt->mnt_fsname, mnt->mnt_dir, mnt->mnt_type,  atoi(mnt->mnt_opts), NULL) == -1) {
                        perror("mount");
                        return 1;
                    }
                }

                // Terminate the reading of the mount table.
                endmntent(fstab);
                break;
            case 't':;
                char* filetype = optarg;
                char* source = argv[j-2];
                char* target = argv[j-1];

                // mount proc filesystem
                if (mount(source, target, optarg, MS_MGC_VAL, NULL) == -1) {
                    perror("mount");
                    return 1;
                }
                
                printf("%s mount on %s successfully\n",source,target);
                break;
            default:
                // others
                break;
        }
    }

    return 0;
}