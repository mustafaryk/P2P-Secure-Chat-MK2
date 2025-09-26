#include <arpa/inet.h>  
#include <netinet/in.h>  
#include <stdio.h>  
#include <string.h>  
#include <sys/socket.h>  
#include <unistd.h>  
#include <signal.h>   
#include <stdlib.h>
#include <openssl/ssl.h>
#include "peer.h"

fd_set all_sockets;				//these variables are global to help with helper functions
fd_set ready_read_sockets;
fd_set ready_write_sockets;
int sfd;
int cfd = -1;
int max_client_queue = 5;

SSL* ssl = NULL;
SSL_CTX* ctx = NULL; 

int main(int argc, char **argv){

	if (argc < 2){  
        fprintf(stderr, "Need port number for you to host on\n");  
        return -1;  
    }
	struct sigaction myaction;      //so that writing to disconnected peer doesnt end server  
    myaction.sa_handler = SIG_IGN;  
    sigaction(SIGPIPE, &myaction, NULL);  

    FD_ZERO(&all_sockets);
	FD_SET(STDIN_FILENO, &all_sockets);				//only read from stdin if data received
	
	sfd = socket(AF_INET, SOCK_STREAM, 0);				//initializing ourselves as a server
	FD_SET(sfd, &all_sockets);  
  
	struct sockaddr_in a;
    memset(&a, 0, sizeof(struct sockaddr_in));      //preamble for setting up server down below  
    a.sin_family = AF_INET;  
    a.sin_port = htons(atoi(argv[1])); // first argument is your port number  
    a.sin_addr.s_addr = htonl(INADDR_ANY);  
  
    if (bind(sfd, (struct sockaddr *)&a, sizeof(struct sockaddr_in)) == -1){		//bind
        fprintf(stderr, "Bind failed\n");  
        return -1;  
    }  
  
    if (listen(sfd, max_client_queue) == -1){			//listen
        fprintf(stderr, "Listen failed\n");  
        return -1;  
    }
	
	printf("Waiting for connection as a server now.\nIf you would like to connect type: \"CONNECT:IP_ADDRESS PORT_NUMBER\"\nIf you would like to disconnect type: \"DISCONNECT\"\nIf you would like to quit type: \"QUIT\"\n");
	
    for(;;){		//loop
		ready_read_sockets = all_sockets;	
		
		if (select(FD_SETSIZE, &ready_read_sockets, NULL, NULL, NULL) == -1){  		//we dont check if client is ready for writing as they could be blocking on purpose
            fprintf(stderr, "select failed for reading and writing\n");  
            return -1;  
        }
		
		if (FD_ISSET(cfd, &ready_read_sockets)){				//peer has sent data, read and process it
			handle_client_data();
		}
		
		if (FD_ISSET(sfd, &ready_read_sockets) && cfd == -1){	//we have an incoming connection and we dont currently have a connection with a peer
			connect_as_server();
		}
		
		if (FD_ISSET(STDIN_FILENO, &ready_read_sockets)){		//we have data in stdin
			if (cfd != -1){				//we have a client so send data to him
				write_to_client();
			}
			else{						//we dont have a client so its an instruction
				handle_input();
			}
		}
		
	}
}