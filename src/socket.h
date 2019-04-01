#ifndef __SOCKET_H_
#define __SOCKET_H_

int socket_install_cb(struct ci_session *ci, void *cb);
int socket_uninstall_cb(struct ci_session *ci);

int socket_init(unsigned int slot_index);
void socket_exit(int socket_fd, unsigned int slot_index);
int socket_client_event(int connection_fd, uint32_t events);
int socket_server_event(int socket_fd, uint32_t events);

#endif
