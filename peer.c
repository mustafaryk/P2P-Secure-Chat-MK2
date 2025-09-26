#include <arpa/inet.h>  
#include <netinet/in.h>  
#include <stdio.h>  
#include <string.h>  
#include <sys/socket.h>  
#include <unistd.h>  
#include <signal.h>   
#include <stdlib.h>
#include <openssl/ssl.h>
#include <openssl/evp.h>
#include <openssl/x509.h>

extern fd_set all_sockets;				//these variables are global to help with helper functions
extern int sfd;
extern int cfd;
extern SSL* ssl;
extern SSL_CTX* ctx;

int message_size_limit = 1024;

void disconnect(){
	if(cfd != -1){
		printf("Peer has disconnected.\n");
		printf("Waiting for connection as a server now.\nIf you would like to connect to a peer, type: \"CONNECT:IP_ADDRESS PORT_NUMBER\"\n");
		FD_CLR(cfd, &all_sockets);
		close(cfd);
		cfd = -1;
	}
	if (ssl != NULL){
		SSL_shutdown(ssl);
		SSL_free(ssl);
		ssl = NULL;
    }
	if (ctx != NULL){
		SSL_CTX_free(ctx);
		ctx = NULL;
    }
}

int connect_as_server(){		//we as a peer are connecting as a server (waiting for a client)
	struct sockaddr_in ca;
	socklen_t sinlen = sizeof(struct sockaddr_in);
	cfd = accept(sfd, (struct sockaddr *)&ca, &sinlen);
	
	ctx = SSL_CTX_new(TLS_server_method());
	EVP_PKEY *pkey = EVP_RSA_gen(2048);         //generate RSA key
	X509 *x509 = X509_new();                    //create a new X509 cert
	X509_set_pubkey(x509, pkey);				//initialise private key
	X509_set_version(x509, 2);
	X509_gmtime_adj(X509_get_notBefore(x509), 0);
	X509_gmtime_adj(X509_get_notAfter(x509), 31536000L);  // 1 year
	X509_NAME *name = X509_get_subject_name(x509);
    X509_NAME_add_entry_by_txt(name, "C",  MBSTRING_ASC, (unsigned char *)"arb", -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "O",  MBSTRING_ASC, (unsigned char *)"arb", -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (unsigned char *)"arb", -1, -1, 0);
    X509_set_issuer_name(x509, name);
	X509_sign(x509, pkey, EVP_sha256());
	SSL_CTX_use_certificate(ctx, x509);			//jargon to feed openssl so it thinks we are legit
	SSL_CTX_use_PrivateKey(ctx, pkey);
	X509_free(x509);
	EVP_PKEY_free(pkey);
    if (ctx == NULL){
		fprintf(stderr, "Error in creating context\n");
		disconnect();
        return 1;
    }
	
	ssl = SSL_new(ctx);
	if (ssl == NULL){
		fprintf(stderr, "Error in creating SSL\n");
		disconnect();
        return 1;
    }
	
	SSL_set_fd(ssl, cfd);
	FD_SET(cfd, &all_sockets);
	
	if (SSL_accept(ssl) <= 0){
		fprintf(stderr, "Error in accepting as server\n");
		disconnect();
		return 1;
	}
	
	char dot_notation[INET_ADDRSTRLEN];
	inet_ntop(AF_INET, &ca.sin_addr, dot_notation, INET_ADDRSTRLEN);
	
	unsigned char custom_message[64] = "Handshake complete... Hello world!\n";		// absolutely essential to do, there is some issue when connecting as client with the buffer, some openssl bullshit
	uint32_t custom_message_length = strlen(custom_message) + 1;
	if (SSL_write(ssl, &custom_message_length, sizeof(custom_message_length)) <= 0){
		fprintf(stderr, "COULD NOT COMPLETE HANDSHAKE\n");
		disconnect();
		return 1;
	}
	if (SSL_write(ssl, custom_message, custom_message_length) <= 0){
		fprintf(stderr, "COULD NOT COMPLETE HANDSHAKE\n");
		disconnect();
		return 1;
	}
	
	printf("Success in connecting to client with IP address: %s and with port number: %d\n", dot_notation, ntohs(ca.sin_port));
	return 0;
}

int connect_as_client(char* ip_address,int port_number){
	cfd = socket(AF_INET, SOCK_STREAM, 0);
	struct sockaddr_in ca;
    memset(&ca, 0, sizeof(struct sockaddr_in));      
    ca.sin_family = AF_INET;   
	ca.sin_port = htons(port_number);

	if (inet_pton(AF_INET, ip_address, &ca.sin_addr) <= 0){
		fprintf(stderr, "Not an IPv4 address");
		disconnect();
		return 1;
	}
	
	if (connect(cfd, (struct sockaddr *)&ca, sizeof(struct sockaddr_in)) == -1){
		fprintf(stderr, "Error in connecting to server with IP address: %s and with port number: %d\n", ip_address, port_number);
		disconnect();
		return 1;
	}
	
	ctx = SSL_CTX_new(TLS_client_method());
    if (ctx == NULL){
		fprintf(stderr, "Error in creating context");
		disconnect();
        return 1;
    }
	SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);  //we wont verify server
	
	ssl = SSL_new(ctx);
	if (ssl == NULL){
		fprintf(stderr, "Error in creating SSL");
		disconnect();
        return 1;
    }
	
	SSL_set_fd(ssl, cfd);
	FD_SET(cfd, &all_sockets);
	if (SSL_connect(ssl) <= 0){
		fprintf(stderr, "Error in connecting as client\n");
		disconnect();
		return 1;
	}
	
	unsigned char custom_message[64] = "Handshake complete... Hello world!\n";		// absolutely essential to do, there is some issue when connecting as client with the buffer, some openssl bullshit
	uint32_t custom_message_length = strlen(custom_message) + 1;
	if (SSL_write(ssl, &custom_message_length, sizeof(custom_message_length)) <= 0){
		fprintf(stderr, "COULD NOT COMPLETE HANDSHAKE\n");
		disconnect();
		return 1;
	}
	if (SSL_write(ssl, custom_message, custom_message_length) <= 0){
		fprintf(stderr, "COULD NOT COMPLETE HANDSHAKE\n");
		disconnect();
		return 1;
	}
	
	printf("Success in connecting to server with IP address: %s and with port number: %d,\n", ip_address, port_number);
	return 0;
}

void write_to_client(){           //helper function to write to our client  
    unsigned char message[message_size_limit];
	uint32_t total_length;
	
    if (fgets(message, sizeof(message), stdin) == NULL){     	//read message from standard input
		return;
    }
	if (strlen(message) == message_size_limit - 1){			// we also have null character at the end due to how fgets work
		fprintf(stderr, "Sending message longer than %d characters, send a shorter message\n", message_size_limit - 1);
		return;
	}
	if (strcmp(message, "DISCONNECT\n") == 0){
		disconnect();
		return;
	}
	if (strcmp(message, "QUIT\n") == 0){
		disconnect();
		exit(0);
	}
	total_length = strlen(message) + 1;
	if (SSL_write(ssl, &total_length, sizeof(total_length)) <= 0 || SSL_write(ssl, message, total_length) <= 0){
		disconnect();
		return;
	}
	
}

void handle_input(){
	char message[message_size_limit];
	char ip_address[32];
	char port_number[32];
    if (fgets(message, sizeof(message), stdin) == NULL){     	//read message from standard input
		return;
    }
	if (strlen(message) == message_size_limit - 1){			// we also have null character at the end due to how fgets work
		fprintf(stderr, "Input longer than %d characters\n", message_size_limit - 1);
		return;
	}
	if (sscanf(message, "CONNECT:%s %s", ip_address, port_number) == 2){
		connect_as_client(ip_address, atoi(port_number));
		return;
	}
	if (strcmp(message, "QUIT\n") == 0){
		disconnect();
		exit(0);
	}
}

void handle_client_data(){
	unsigned char message[message_size_limit];
	uint32_t total_length;
	if (SSL_read(ssl, &total_length, sizeof(total_length)) <= 0){
			disconnect();
			return;
	}
	if (total_length >= message_size_limit){
		fprintf(stderr, "Peer sent message longer than acceptable total length: %d\n", message_size_limit);
		disconnect();
		return;
	}
	if (SSL_read(ssl, message, total_length) <=0){
		disconnect();
		return;
	}
	printf("PEER: %s", message);
	
}