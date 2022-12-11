#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>
#include <ctype.h>

#define BUFFER_SIZE 4096


int main(int argc, char *argv[])
{
	if (argc != 3) {
		fprintf(stderr, "2 arguments required: {pid} struct_name={page | vm_area_struct}\n");
		return 1;
	}

	int pid = atoi(argv[1]);
	char *struct_name = argv[2];
	int struct_id;

	if (pid == 0 && !isdigit(argv[1][0])) {
		fprintf(stderr, "{pid} should be a number\n");
		return 1;
	}

	if (strcmp(struct_name, "page") == 0)
		struct_id = 0;
	else if (strcmp(struct_name, "vm_area_struct") == 0)
		struct_id = 1;
	else {
		fprintf(stderr, "{struct_name} should be /page/ or /vm_area_struct/\n");
		return 1;
	}
	
	int fd = open("/proc/my_module", O_RDWR);
	if (fd == -1) {
		fprintf(stderr, "fopen: /proc/my_module opening error\n");
		close(fd);
		return 1;
	}
	char buf[BUFFER_SIZE];
	sprintf(buf, "%d %d", pid, struct_id);

	if (write(fd, buf, strlen(buf)) == -1) {
		fprintf(stderr, "Writing buffer=\"%s\" to fd=%d failed\n", buf, fd);
		close(fd);
		return 1;
	}

	if (read(fd, buf, BUFFER_SIZE) == -1) {
		fprintf(stderr, "Reading from fd=%d failed\n", fd);
		close(fd);
		return 1;
	} 
	printf("--- PID=%d STRUCT=%s ---\n\n%s", pid, struct_name, buf);

	close(fd);

	return 0;
}





