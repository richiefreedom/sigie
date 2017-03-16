#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>

#include "sigie.h"

#define SIGIE_BACKLOG     10
#define SIGIE_MIN_RECEIVE 16

#define SIGIE_BUFFER_ALLOC_GRANULARITY 512
#define SIGIE_BUFFER_ALLOC_MAX (1024 * 1024 * 64)

struct sigie_connection {
	struct sockaddr_in sock_address;
	int sock_fd;
};

struct sigie_buffer {
	char *data;
	char *variables;
	char *content;
	size_t allocated_bytes;
	size_t used_bytes;
};

struct sigie_buffer *sigie_buffer_create(void)
{
	struct sigie_buffer *buff;

	buff = malloc(sizeof(*buff));
	if (!buff) {
		perror("[error] Cannot allocate new sigie buffer");
		return NULL;
	}

	buff->data = malloc(SIGIE_BUFFER_ALLOC_GRANULARITY);
	if (!buff->data) {
		perror("[errror] Cannot allocate sigie buffer storage");
		free(buff);
		return NULL;
	}

	buff->allocated_bytes = SIGIE_BUFFER_ALLOC_GRANULARITY;
	buff->used_bytes = 0;
	buff->content = NULL;

	return buff;
}

int sigie_buffer_extend(struct sigie_buffer *buff, size_t needed_bytes)
{
	char *relocated_data;
	size_t rest;

	if (buff->allocated_bytes >= needed_bytes)
		return 0;

	rest = needed_bytes % SIGIE_BUFFER_ALLOC_GRANULARITY;
	needed_bytes += SIGIE_BUFFER_ALLOC_GRANULARITY - rest;

	if (needed_bytes >= SIGIE_BUFFER_ALLOC_MAX) {
		fprintf(stderr, "[error] Library uses too much memory\n");
		return -1;
	}

	relocated_data = malloc(needed_bytes);
	if (!relocated_data) {
		perror("[error] Cannot relocate sigie buffer data");
		return -1;
	}

	memcpy(relocated_data, buff->data, buff->allocated_bytes);

	buff->variables = relocated_data + (buff->variables - buff->data);
	if (buff->content) {
		buff->content = relocated_data + (buff->content - buff->data);
	}

	free(buff->data);
	buff->data = relocated_data;
	buff->allocated_bytes = needed_bytes;

	return 0;
}

void sigie_buffer_destroy(struct sigie_buffer *buff)
{
	free(buff->data);
	free(buff);
}

char *sigie_buffer_get_content(struct sigie_buffer *buff)
{
	return buff->content;
}

struct sigie_connection *sigie_connection_create(uint16_t port)
{
	struct sigie_connection *conn;
	int ret;

	conn = malloc(sizeof(*conn));
	if (!conn) {
		perror("[error] Cannot alloc new sigie connection");
		goto error;
	}

	memset(conn, 0, sizeof(*conn));

	conn->sock_fd = socket(AF_INET, SOCK_STREAM, 0);
	if (-1 == conn->sock_fd) {
		perror("[error] Cannot create server socket");
		goto error_free_conn;
	}

	conn->sock_address.sin_family = AF_INET;
	conn->sock_address.sin_addr.s_addr = htons(INADDR_ANY);
	conn->sock_address.sin_port = htons(port);

	ret = bind(conn->sock_fd, (struct sockaddr *) &conn->sock_address,
		sizeof(conn->sock_address));
	if (-1 == ret) {
		perror("[error] Cannot bind the server socket");
		goto error_close_fd;
	}

	ret = listen(conn->sock_fd, SIGIE_BACKLOG);
	if (-1 == ret) {
		perror("[error] Cannot start to listen on the server socket");
		goto error_close_fd;
	}

	return conn;

error_close_fd:
	close(conn->sock_fd);
error_free_conn:
	free(conn);
error:
	return NULL;
}

void sigie_connection_destroy(struct sigie_connection *conn)
{
	close(conn->sock_fd);
	free(conn);
}

int sigie_accept(struct sigie_connection *conn)
{
	int io_sock_fd;

	io_sock_fd = accept(conn->sock_fd, (struct sockaddr *) NULL, NULL);
	if (-1 == io_sock_fd)
		perror("[error] Cannot accept incoming connection");

	return io_sock_fd;
}

void sigie_close(int io_sock_fd)
{
	close(io_sock_fd);
}

int sigie_read(int io_sock_fd, char *buffer, size_t bytes_to_read)
{
	ssize_t read_bytes;

	while (bytes_to_read) {
		read_bytes = read(io_sock_fd, buffer, bytes_to_read);
		if (-1 == read_bytes) {
			perror("[error] Cannot read bytes from IO socket");
			return -1;
		}

		bytes_to_read -= read_bytes;
	}

	return 0;
}

int sigie_write(int io_sock_fd, char *buffer, size_t bytes_to_write)
{
	ssize_t written_bytes;

	while (bytes_to_write) {
		written_bytes = write(io_sock_fd, buffer, bytes_to_write);
		if (-1 == written_bytes) {
			perror("[error] Cannot read bytes from IO socket");
			return -1;
		}

		bytes_to_write -= written_bytes;
	}

	return 0;
}

int sigie_receive(int io_sock_fd, struct sigie_buffer *buff)
{
	long int netstring_length;
	size_t read_bytes = 0;
	size_t bytes_to_read;
	size_t num_len;
	char *end_ptr;
	int ret;

	ret = sigie_read(io_sock_fd, buff->data, SIGIE_MIN_RECEIVE);
	if (-1 == ret)
		return -1;

	read_bytes += SIGIE_MIN_RECEIVE;

	netstring_length = strtol(buff->data, &end_ptr, 10);
	if (*end_ptr != ':') {
		fprintf(stderr, "[error] Incorrect netstring length\n");
		return -1;
	}

	buff->variables = end_ptr + 1;

	num_len = (end_ptr - buff->data) + 1;
	bytes_to_read = netstring_length;
	bytes_to_read -= SIGIE_MIN_RECEIVE - num_len;

	ret = sigie_buffer_extend(buff, num_len + netstring_length);
	if (-1 == ret)
		return -1;

	ret = sigie_read(io_sock_fd, buff->data + SIGIE_MIN_RECEIVE,
		bytes_to_read);
	if (-1 == ret)
		return -1;

	read_bytes += bytes_to_read;

	if (read_bytes != num_len + netstring_length) {
		fprintf(stderr, "[error] Internal inconsitence\n");
		fprintf(stderr, "\t%lu != %lu\n", read_bytes,
			num_len + netstring_length);
	}

	buff->used_bytes = read_bytes;

	return 0;
}

void sigie_print_variables(struct sigie_buffer *buff)
{
	char *max_data_ptr = (buff->content) ? (buff->content - 1) :
		buff->data + buff->used_bytes;
	char *next_variable = buff->variables;

	while (next_variable < max_data_ptr) {
		size_t var_length;

		printf("%s:", next_variable);

		var_length = strlen(next_variable);
		next_variable += var_length + 1;

		if (next_variable >= max_data_ptr) {
			fprintf(stderr, "[error] Incorrect sigie input\n");
			abort();
		}

		printf("%s;\n", next_variable);

		var_length = strlen(next_variable);
		next_variable += var_length + 1;
	}
}

char *sigie_get_variable(struct sigie_buffer *buff, char *name)
{
	char *max_data_ptr = (buff->content) ? (buff->content - 1) :
		buff->data + buff->used_bytes;
	char *next_variable = buff->variables;

	while (next_variable < max_data_ptr) {
		size_t var_length;
		int found = 0;

		if (0 == strcmp(next_variable, name))
			found = 1;

		var_length = strlen(next_variable);
		next_variable += var_length + 1;

		if (next_variable >= max_data_ptr) {
			fprintf(stderr, "[error] Incorrect sigie input\n");
			abort();
		}

		if (found)
			return next_variable;

		var_length = strlen(next_variable);
		next_variable += var_length + 1;
	}

	return NULL;
}

int sigie_receive_content(int io_sock_fd, struct sigie_buffer *buff)
{
	long int content_length;
	char *variable;
	char *end_ptr;
	int ret;

	variable = sigie_get_variable(buff, "CONTENT_LENGTH");
	if (!variable) {
		fprintf(stderr, "[error] Cannot obtain content length\n");
		return -1;
	}

	content_length = strtol(variable, &end_ptr, 10);
	if (*end_ptr != '\0') {
		fprintf(stderr, "[error] Incorrect content length\n");
		fprintf(stderr, "\tend_ptr points to %s\n", end_ptr);
		return -1;
	}

	/* We need one more character position for '\0' at the end. */
	ret = sigie_buffer_extend(buff, buff->used_bytes + content_length + 2);
	if (-1 == ret)
		return -1;

	/* We have to read all the content and ',' before the content. */
	ret = sigie_read(io_sock_fd, buff->data + buff->used_bytes,
			content_length + 1);
	if (-1 == ret)
		return -1;

	buff->content = buff->data + buff->used_bytes + 1;
	buff->used_bytes += content_length + 2;
	buff->data[buff->used_bytes - 1] = '\0';

	return 0;
}
