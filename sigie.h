#ifndef __SIGIE_H__
#define __SIGIE_H__

#include <stdint.h>

struct sigie_buffer *sigie_buffer_create(void);
int sigie_buffer_extend(struct sigie_buffer *buff, size_t needed_bytes);
void sigie_buffer_destroy(struct sigie_buffer *buff);

struct sigie_connection *sigie_connection_create(uint16_t port);
void sigie_connection_destroy(struct sigie_connection *conn);

int sigie_accept(struct sigie_connection *conn);
void sigie_close(int io_sock_fd);
int sigie_read(int io_sock_fd, char *buffer, size_t bytes_to_read);
int sigie_write(int io_sock_fd, char *buffer, size_t bytes_to_write);

int sigie_receive(int io_sock_fd, struct sigie_buffer *buff);

void sigie_print_variables(struct sigie_buffer *buff);
char *sigie_get_variable(struct sigie_buffer *buff, char *name);
int sigie_receive_content(int io_sock_fd, struct sigie_buffer *buff);

#endif
