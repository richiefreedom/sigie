#include <stdio.h>
#include <string.h>

#include "sigie.h"

#define PORT 8000

int main(void)
{
	char *response = "Status: 200 OK\r\nContent-Type: text/plain\r\n\r\n42";
	struct sigie_buffer *buffer = NULL;
	struct sigie_connection *conn;
	int io_sock_fd = -1;
	int err = 0;
	int ret;

	conn = sigie_connection_create(PORT);
	if (!conn)
		return 1;

	while (1) {
		buffer = sigie_buffer_create();
		if (!buffer) {
			err = 2;
			goto out;
		}

		io_sock_fd = sigie_accept(conn);
		if (-1 == io_sock_fd) {
			err = 3;
			goto out;
		}

		printf("Connection accepted.\n");

		ret = sigie_receive(io_sock_fd, buffer);
		if (-1 == ret) {
			err = 4;
			goto out;
		}

		sigie_print_variables(buffer);

		printf("Content length: %s.\n",
				sigie_get_variable(buffer, "CONTENT_LENGTH"));

		ret = sigie_receive_content(io_sock_fd, buffer);
		if (-1 == ret) {
			err = 5;
			goto out;
		}

		ret = sigie_write(io_sock_fd, response, strlen(response));
		if (-1 == ret) {
			err = 6;
			goto out;
		}

		sigie_close(io_sock_fd);
		sigie_buffer_destroy(buffer);

		printf("Connection closed.\n");

		io_sock_fd = -1;
		buffer = NULL;
	}

out:
	if (-1 != io_sock_fd)
		sigie_close(io_sock_fd);

	if (buffer)
		sigie_buffer_destroy(buffer);

	sigie_connection_destroy(conn);

	return err;
}
