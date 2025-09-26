#ifndef _PEER_H
#define _PEER_H
void disconnect();
int connect_as_server();
int connect_as_client(char* ip_address,int port_number);
void write_to_client();
void handle_input();
void handle_client_data();
#endif