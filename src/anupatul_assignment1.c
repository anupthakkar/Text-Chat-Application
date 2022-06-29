/**
 * @anupatul_assignment1
 * @author  Anup Atul Thakkar <anupatul@buffalo.edu>
 * @version 1.0
 *
 * @section LICENSE
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of
 * the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details at
 * http://www.gnu.org/copyleft/gpl.html
 *
 * @section DESCRIPTION
 *
 * This contains the main function. Add further description here....
 */
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <string.h>
#include <unistd.h>
#include <strings.h>
#include <sys/un.h>
#include <ifaddrs.h>
#include <errno.h>
#include <ctype.h>
#include <stdbool.h>

#define STDIN 0 

#include "../include/global.h"
#include "../include/logger.h"

/**
 * main function
 *
 * @param  argc Number of arguments
 * @param  argv The argument list
 * @return 0 EXIT_SUCCESS
 */

void call_client(char *port);
void call_server(char *port);
bool is_valid_ip_address(char *ip);
bool is_valid_port(char *port);
int connect_server(char *ip, char *port);
char * get_ip_address();
char * get_port_number();
int main_socketfd;
void *get_in_addr(struct sockaddr *sa);
#define IP_LEN 32
#define STDIN 0
#define MSG_SIZE 256
int client_socketfd;
#define MAXDATASIZE 256
int client_accepted = -1;
void sort_list();
void sort_blocked_list();

struct host {
	// struct host * blocked[5];
    char blocked[5][32];
	struct host * next_host[5];
	char* hostname;
	char* ip_addr;
	char* port_num;
	int num_msg_sent;
	int num_msg_rcv;
	char* status;
	int fd;
	// int blocked_counter = 0;
	// int next_host_counter = 0;
	bool is_logged_in;
	bool is_server;
	struct message * queued_messages;
    int queued_count;
	int id;
}*host_ptr[5];

struct host list_array[5];

struct message {
	char text[MAXDATASIZE];
	// struct host from_client;
    char from_ip_addr[32];
    char to_ip_addr[32];
    char from_port[6];
    char to_port[6];
    char msg[256];
	struct message * next_message;
	bool is_broadcast;
};

struct refresh_list {
    int id;
    char ip[32];
    char port[6];
    char hostname[100];
    bool logged_in;
};


struct blocked {
    char hostname[100];
    char ip[32];
    char port[6];
};

struct blocked blocked_list[5];

int main(int argc, char **argv)
{
	/*Init. Logger*/
	cse4589_init_log(argv[2]);

	/*Clear LOGFILE*/
	fclose(fopen(LOGFILE, "w"));

	/*Start Here*/
	if(argc == 3){
		if(*argv[1] == 'c'){
			call_client(argv[2]);
		}
		else if(*argv[1] == 's'){
			// printf("invoke server at %d ",atoi(argv[2]));
			call_server(argv[2]);
		}
		else{
			printf("please select server or client");
		}
	} else {
		printf("Please pass the correct number of arguments\n");
	}

	return 0;
}

void call_client(char *port){
	struct host a;
	a.port_num = NULL;
	a.ip_addr = NULL;
	a.is_server = false;
	struct addrinfo address, *res;
    struct message message;
	memset(&address, 0, sizeof address);
	address.ai_family = AF_UNSPEC;  // use IPv4 or IPv6, whichever
	address.ai_socktype = SOCK_STREAM;
	address.ai_flags = AI_PASSIVE;
    int server;
    bool first_login_done = false;
    for(int i=0;i<5;i++)
    {
        list_array[i].id=0;
    }

	getaddrinfo(NULL, port, &address, &res);

	main_socketfd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
	
	if(main_socketfd == -1){
		perror("Socket creation failed");
	}
	a.fd = main_socketfd;
	int result = bind(main_socketfd, res->ai_addr, res->ai_addrlen);
	if(result == -1){
		perror("Binding of socket failed");
	}

    fd_set master, read_fds;
    FD_ZERO(&master); 
    FD_ZERO(&read_fds);
    FD_SET(STDIN, &master);
    FD_SET(main_socketfd+1, &master);
    int fdmax = main_socketfd;

    struct message recivied_message;
    memset(&recivied_message, '\0', sizeof(recivied_message));
	
    while(true){

        // FD_ZERO(&master); 
        // FD_ZERO(&read_fds);
        // FD_SET(STDIN, &master);
        // FD_SET(main_socketfd+1, &master);
        

        fflush(stdout);
        read_fds = master;
        if (select(fdmax+1, &read_fds, NULL, NULL, NULL) == -1) {
            perror("Failed to select server");
            exit(4);
        }
        // printf("FDMAX: %d\n", fdmax);
        for(int i = 0; i <= fdmax; i++) {
            if (FD_ISSET(i, &read_fds)) { // we got one!!
                if(STDIN == i){
                    char *input = (char*) malloc(sizeof(char)*256);
                    memset(input, '\0', 2565);
                    fgets(input, 255, stdin);
                    int length = strlen(input);
                    input[length - 1] = '\0';
                    
                    if(strncmp(input, "LOGIN", 5) == 0){
                        char ip[32];
                        char port[6];
                        int i = 0;
                        int j = 6;
                        while(input[j] != ' '){
                            ip[i++] = input[j++];
                        }
                        ip[i] = '\0';
                        i = 0;
                        j += 1;
                        while(input[j] != '\0'){
                            port[i++] = input[j++]; 
                        }
                        port[i] = '\0';
                        bool ipvalid = is_valid_ip_address(ip);
                        bool portvalid = is_valid_port(port);
                        if(!ipvalid || !portvalid){
                            cse4589_print_and_log("[%s:ERROR]\n", "LOGIN");
                            cse4589_print_and_log("[%s:END]\n", "LOGIN");
                            continue;
                        }
                        int port_number = atoi(port);
                        if(port_number < 1 || port_number > 65535){
                            cse4589_print_and_log("[%s:ERROR]\n", "LOGIN");
                            cse4589_print_and_log("[%s:END]\n", "LOGIN");
                            continue;
                        }
                        if(first_login_done){
                            // printf("Inside first login done\n");
                            a.is_logged_in = true;
                            strcpy(message.from_port, a.port_num);
                            strcpy(message.from_ip_addr, a.ip_addr);
                            strcpy(message.text, "RELOGIN");
                            int send_info = send(server, &message, sizeof(message), 0);
                            struct refresh_list list[5]; 
                            memset(&list, '\0', sizeof(list));
                            int recv_status = recv(server, &list, sizeof(list), 0);
                            // printf("Received list from server \n");
                            int c = 0;
                            for(int i=0;i<5;i++)
                            {
                                if(list[i].id!=0)
                                {
                                    // printf("Client info received %d\n",i);
                                    list_array[c].id = list[i].id;
                                    list_array[c].hostname = malloc(100);
                                    list_array[c].ip_addr = malloc(32);
                                    list_array[c].port_num = malloc(6);
                                    strcpy(list_array[c].hostname, list[i].hostname);
                                    strcpy(list_array[c].ip_addr, list[i].ip);
                                    strcpy(list_array[c].port_num, list[i].port);
                                    c++;
                                }
                            }
                            // cse4589_print_and_log("[%s:SUCCESS]\n", "LOGIN");
                            // cse4589_print_and_log("[%s:END]\n", "LOGIN");
                            continue;
                        }
                        // printf("Connecting to server\n");
                        int connect_result = connect_server(ip, port);
                        server = connect_result;
                        if(connect_result == -1){
                            cse4589_print_and_log("[%s:ERROR]\n", "LOGIN");
                            cse4589_print_and_log("[%s:END]\n", "LOGIN");
                            continue;
                        } else {
                            a.port_num = malloc(6);
                            a.ip_addr = malloc(32);
                            a.hostname = malloc(100);
                            // message.from_client = malloc(sizeof(a));
                            a.is_logged_in = true;
                            char * port_number;
                            char * ip_address;
                            port_number = get_port_number();
                            strcpy(message.from_port, port_number);
                            strcpy(a.port_num, port_number);
                            ip_address = get_ip_address();
                            strcpy(message.from_ip_addr, ip_address);
                            strcpy(a.ip_addr, ip_address);
                            strcpy(message.text, "CLIENT_PORT");
                            char host[100];
                            int hostname = gethostname(host, sizeof(host));
                            // printf("Client Hoatname is: %s\n",host);
                            strcpy(a.hostname, host);
                            int send_info = send(server, &message, sizeof(message), 0);
                            if(send_info==sizeof(message)){
                                // printf("Message sent successfully\n");
                                struct refresh_list list[5]; 
                                memset(&list, '\0', sizeof(list));
                                int recv_status = recv(server, &list, sizeof(list), 0);
                                // printf("Received list from server \n");
                                if(recv_status > 0){
                                    int c = 0;
                                    for(int i=0;i<5;i++)
                                    {
                                        if(list[i].id!=0 && list[i].logged_in)
                                        {
                                            // printf("Client info received %d\n",i);
                                            list_array[c].id = list[i].id;
                                            list_array[c].hostname = malloc(100);
                                            list_array[c].ip_addr = malloc(32);
                                            list_array[c].port_num = malloc(6);
                                            list_array[c].is_logged_in = list[i].logged_in;
                                            strcpy(list_array[c].hostname, list[i].hostname);
                                            strcpy(list_array[c].ip_addr, list[i].ip);
                                            strcpy(list_array[c].port_num, list[i].port);
                                            c++;
                                        }
                                    }
                                    first_login_done = true;
                                    cse4589_print_and_log("[%s:SUCCESS]\n", "LOGIN");
                                    cse4589_print_and_log("[%s:END]\n", "LOGIN");
                                    FD_SET(server, &master);
                                    if(server > fdmax){
                                        fdmax = server;
                                    }
                                } else {
                                    cse4589_print_and_log("[%s:ERROR]\n", "LOGIN");
                                    cse4589_print_and_log("[%s:END]\n", "LOGIN");
                                }

                            } 
                            else {
                                cse4589_print_and_log("[%s:ERROR]\n", "LOGIN");
                                cse4589_print_and_log("[%s:END]\n", "LOGIN");
                            }
                            continue;
                        }
                    }
                    else if(strcmp(input, "AUTHOR") == 0){
                        cse4589_print_and_log("[%s:SUCCESS]\n", "AUTHOR");
                        cse4589_print_and_log("I, %s, have read and understood the course academic integrity policy.\n", "anupatul");
                        cse4589_print_and_log("[%s:END]\n", "AUTHOR");
                    }
                    else if(strcmp(input, "IP") == 0){
                        char* ip_address;
                        if(a.ip_addr != NULL){
                            ip_address = a.ip_addr;
                        }
                        else{
                            ip_address = get_ip_address();
                            a.ip_addr = malloc(32);
                            strcpy(a.ip_addr, ip_address);
                        }
                        if(ip_address){
                            cse4589_print_and_log("[%s:SUCCESS]\n", "IP");
                            cse4589_print_and_log("IP:%s\n", ip_address);
                            cse4589_print_and_log("[%s:END]\n", "IP");
                        }
                        else {
                            cse4589_print_and_log("[%s:ERROR]\n", "IP");
                            cse4589_print_and_log("[%s:END]\n", "IP");
                        }
                        
                    }
                    else if(strcmp(input, "PORT") == 0){
                        char* port;
                        if(a.port_num != NULL){
                            port = a.port_num;
                        }
                        else{
                            a.port_num = malloc(6);
                            port = get_port_number();
                            strcpy(a.port_num, port);
                        }
                        if(port){
                            cse4589_print_and_log("[%s:SUCCESS]\n", "PORT");
                            cse4589_print_and_log("PORT:%s\n", port);
                            cse4589_print_and_log("[%s:END]\n", "PORT");
                        }
                        else {
                            cse4589_print_and_log("[%s:ERROR]\n", "PORT");
                            cse4589_print_and_log("[%s:END]\n", "PORT");
                        }
                    }
                    else if(strcmp(input, "LIST") == 0){
                        if(a.is_logged_in){
                            cse4589_print_and_log("[%s:SUCCESS]\n", "LIST");
                            sort_list();
                            int g = 1;
                            for(int i=0;i<5;i++)
                            {
                                if(list_array[i].id!=0 && list_array[i].is_logged_in)
                                {   
                                    cse4589_print_and_log("%-5d%-35s%-20s%-8s\n" , g++, list_array[i].hostname, list_array[i].ip_addr, list_array[i].port_num);
                                }
                            }
                            cse4589_print_and_log("[%s:END]\n", "LIST");
                        } else{
                            cse4589_print_and_log("[%s:ERROR]\n", "LIST");
                            cse4589_print_and_log("[%s:END]\n", "LIST");
                        }
                    }
                    else if(strcmp(input, "REFRESH") == 0){
                        if(a.is_logged_in){
                            for(int i=0;i<5;i++)
                            {
                                list_array[i].id=0;
                            }
                            strcpy(message.text,"REFRESH");
                            int send_info = send(server, &message, sizeof(message), 0);
                            // printf("Message sent\n");
                            struct refresh_list list[5]; 
                            memset(&list, '\0', sizeof(list));
                            int recv_status = recv(server, &list, sizeof(list), 0);
                            // printf("Message received %d\n", recv_status);
                            if(recv_status > 0){
                                cse4589_print_and_log("[%s:SUCCESS]\n", "REFRESH");
                                int c = 0;
                                for(int i=0;i<5;i++)
                                {
                                    if(list[i].id!=0)
                                    {
                                        list_array[c].id = list[i].id;
                                        list_array[c].hostname = malloc(100);
                                        list_array[c].ip_addr = malloc(32);
                                        list_array[c].port_num = malloc(6);
                                        list_array[c].is_logged_in = list[i].logged_in;
                                        strcpy(list_array[c].hostname, list[i].hostname);
                                        strcpy(list_array[c].ip_addr, list[i].ip);
                                        strcpy(list_array[c].port_num, list[i].port);
                                        c++;
                                    }
                                }
                                cse4589_print_and_log("[%s:END]\n", "REFRESH");
                            } 
                            else{
                                cse4589_print_and_log("[%s:ERROR]\n", "REFRESH");
                                cse4589_print_and_log("[%s:END]\n", "REFRESH");
                            }
                        } else {
                            cse4589_print_and_log("[%s:ERROR]\n", "REFRESH");
                            cse4589_print_and_log("[%s:END]\n", "REFRESH");
                        }
                    }
                
                    else if(strncmp(input, "SEND", 4) == 0){
                        if(a.is_logged_in){
                            // printf("Inside Send\n");
                            char ip[32];
                            char msg[256];
                            int i = 0;
                            int j = 5;
                            while(input[j] != ' '){
                                ip[i++] = input[j++];
                            }
                            ip[i] = '\0';
                            i = 0;
                            j += 1;
                            while(input[j] != '\0'){
                                msg[i++] = input[j++]; 
                            }
                            msg[i] = '\0';
                            bool ipvalid = is_valid_ip_address(ip);
                            if(!ipvalid){
                                cse4589_print_and_log("[%s:ERROR]\n", "SEND");
                                cse4589_print_and_log("[%s:END]\n", "SEND");
                                continue;
                            }
                            bool ip_present = false;
                            for(int j = 0; j < 5; j++){
                                if(list_array[j].id != 0){
                                    if(strcmp(ip, list_array[j].ip_addr) == 0){
                                        ip_present = true;
                                        break;
                                    }
                                }
                            }
                            if(!ip_present){
                                cse4589_print_and_log("[%s:ERROR]\n", "SEND");
                                cse4589_print_and_log("[%s:END]\n", "SEND");
                                continue;
                            }
                            strcpy(message.text,"SEND");
                            strcpy(message.from_ip_addr, a.ip_addr);
                            strcpy(message.from_port, a.port_num);
                            strcpy(message.to_ip_addr, ip);
                            strcpy(message.msg, msg);
                            int send_info = send(server, &message, sizeof(message), 0);
                            cse4589_print_and_log("[%s:SUCCESS]\n", "SEND");
                            cse4589_print_and_log("[%s:END]\n", "SEND");
                        } else {
                            cse4589_print_and_log("[%s:ERROR]\n", "SEND");
                            cse4589_print_and_log("[%s:END]\n", "SEND");
                        }

                    }
                    else if(strcmp(input, "LOGOUT") == 0){
                        if(a.is_logged_in){
                            a.is_logged_in = false;
                            strcpy(message.text, "LOGOUT");
                            strcpy(message.from_ip_addr,a.ip_addr);
                            int send_info = send(server, &message, sizeof(message), 0);
                            cse4589_print_and_log("[%s:SUCCESS]\n", "LOGOUT");
                            cse4589_print_and_log("[%s:END]\n", "LOGOUT");
                        } else {
                            cse4589_print_and_log("[%s:ERROR]\n", "LOGOUT");
                            cse4589_print_and_log("[%s:END]\n", "LOGOUT");
                        }
                    }
                    else if(strcmp(input, "EXIT") == 0){
                        strcpy(message.text, "EXIT");
                        strcpy(message.from_ip_addr,a.ip_addr);
                        int send_info = send(server, &message, sizeof(message), 0);
                        close(server);
                        cse4589_print_and_log("[%s:SUCCESS]\n", "EXIT");
                        cse4589_print_and_log("[%s:END]\n", "EXIT");
                        exit(0);
                    }
                    else if(strncmp(input, "BROADCAST", 9) == 0){
                        if(a.is_logged_in){
                            strcpy(message.text, "BROADCAST");
                            char msg[256];
                            int i = 0;
                            int j = 10;
                            while(input[j] != '\0'){
                                msg[i++] = input[j++]; 
                            }
                            msg[i] = '\0';
                            strcpy(message.from_ip_addr, a.ip_addr);
                            strcpy(message.msg, msg);
                            int send_info = send(server, &message, sizeof(message), 0);
                            cse4589_print_and_log("[%s:SUCCESS]\n", "BROADCAST");
                            cse4589_print_and_log("[%s:END]\n", "BROADCAST");
                        } else {
                            cse4589_print_and_log("[%s:ERROR]\n", "BROADCAST");
                            cse4589_print_and_log("[%s:END]\n", "LOGOUT");
                        }
                    }
                    else if(strncmp(input, "BLOCK", 5) == 0){
                        if(a.is_logged_in){
                            strcpy(message.text, "BLOCK");
                            char ip[32];
                            int i = 0;
                            int j = 6;
                            while(input[j] != '\0'){
                                ip[i++] = input[j++]; 
                            }
                            ip[i] = '\0';
                            bool ipvalid = is_valid_ip_address(ip);
                            if(!ipvalid){
                                cse4589_print_and_log("[%s:ERROR]\n", "BLOCK");
                                cse4589_print_and_log("[%s:END]\n", "BLOCK");
                                continue;
                            }
                            bool ip_present = false;
                            bool ip_blocked = false;
                            for(int x=0; x<5; x++){
                                if(list_array[x].id != 0){
                                    if(strcmp(list_array[x].ip_addr, ip) == 0){
                                        ip_present = true;
                                        break;
                                    }
                                }
                            }
                            for(int x=0; x<5; x++){
                                // if(list_array[x].id != 0){
                                //     if(strcmp(list_array[x].ip_addr, a.ip_addr) == 0){
                                //         for(int h=0; h<5; h++){
                                //             if(strcmp(ip, list_array[x].blocked[h]) == 0){
                                //                 ip_blocked = true;
                                //                 break;
                                //             }
                                //         }
                                //         if(ip_blocked){
                                //             break;
                                //         }
                                //     }
                                // }
                                if(strcmp(a.blocked[x], ip) == 0){
                                    ip_blocked = true;
                                    break;
                                }
                            }
                            if(!ip_present || ip_blocked){
                                cse4589_print_and_log("[%s:ERROR]\n", "BLOCK");
                                cse4589_print_and_log("[%s:END]\n", "BLOCK");
                                continue;
                            }
                            strcpy(message.from_ip_addr, a.ip_addr);
                            strcpy(message.to_ip_addr, ip);
                            int send_info = send(server, &message, sizeof(message), 0);
                            for(int k=0; k<5; k++){
                                if(strlen(a.blocked[k]) == 0){
                                    strcpy(a.blocked[k], ip);
                                    break;
                                }
                            }
                            cse4589_print_and_log("[%s:SUCCESS]\n", "BLOCK");
                            cse4589_print_and_log("[%s:END]\n", "BLOCK");
                        } else {
                            cse4589_print_and_log("[%s:ERROR]\n", "BLOCK");
                            cse4589_print_and_log("[%s:END]\n", "BLOCK");
                        }
                    }
                    else if(strncmp(input, "UNBLOCK ", 7) == 0){
                        if(a.is_logged_in){
                            strcpy(message.text, "UNBLOCK");
                            char ip[32];
                            int i = 0;
                            int j = 8;
                            while(input[j] != '\0'){
                                ip[i++] = input[j++]; 
                            }
                            ip[i] = '\0';
                            bool ipvalid = is_valid_ip_address(ip);
                            if(!ipvalid){
                                cse4589_print_and_log("[%s:ERROR]\n", "UNBLOCK");
                                cse4589_print_and_log("[%s:END]\n", "UNBLOCK");
                                continue;
                            }
                            bool ip_present = false;
                            bool ip_blocked = false;
                            for(int x=0; x<5; x++){
                                if(list_array[x].id != 0){
                                    if(strcmp(list_array[x].ip_addr, ip) == 0){
                                        ip_present = true;
                                        break;
                                    }
                                }
                            }
                            for(int x=0; x<5; x++){
                                // if(list_array[x].id != 0){
                                //     if(strcmp(list_array[x].ip_addr, a.ip_addr) == 0){
                                //         for(int h=0; h<5; h++){
                                //             if(strcmp(ip, list_array[x].blocked[h]) == 0){
                                //                 ip_blocked = true;
                                //                 break;
                                //             }
                                //         }
                                //         if(ip_blocked){
                                //             break;
                                //         }
                                //     }
                                // }
                                if(strcmp(a.blocked[x], ip) == 0){
                                    ip_blocked = true;
                                    break;
                                }
                            }
                            if(!ip_present || !ip_blocked){
                                cse4589_print_and_log("[%s:ERROR]\n", "UNBLOCK");
                                cse4589_print_and_log("[%s:END]\n", "UNBLOCK");
                                continue;
                            }
                            strcpy(message.from_ip_addr, a.ip_addr);
                            strcpy(message.to_ip_addr, ip);
                            int send_info = send(server, &message, sizeof(message), 0);
                            for(int k=0; k<5; k++){
                                if(strcmp(a.blocked[k], ip) == 0){
                                    strcpy(a.blocked[k], "");
                                    break;
                                }
                            }
                            cse4589_print_and_log("[%s:SUCCESS]\n", "UNBLOCK");
                            cse4589_print_and_log("[%s:END]\n", "UNBLOCK");
                        } else {
                            cse4589_print_and_log("[%s:ERROR]\n", "UNBLOCK");
                            cse4589_print_and_log("[%s:END]\n", "UNBLOCK");
                        }
                    }
                }
                else{
                    // printf("Inside receive\n");
                    // printf("Hello World -_-\n");
                    // printf("max_socketID: %d, Server: %d\n",main_socketfd, server);
                    // printf("%d\n",recv(server, &recivied_message, sizeof(recivied_message), 0));
                    int recv_status = recv(server, &recivied_message, sizeof(recivied_message), 0);
                    // printf("recv_status: %d, TEXT IN CLIENT: %s\n", recv_status, recivied_message.text);
                    if(strcmp(recivied_message.text, "RECEIVED") == 0){
                        cse4589_print_and_log("[%s:SUCCESS]\n", "RECEIVED");
                        cse4589_print_and_log("msg from:%s\n[msg]:%s\n", recivied_message.from_ip_addr, recivied_message.msg);
                        cse4589_print_and_log("[%s:END]\n", "RECEIVED");
                    } else if(strcmp(recivied_message.text, "Buffer Completed") == 0){
                        cse4589_print_and_log("[%s:SUCCESS]\n", "LOGIN");
                        cse4589_print_and_log("[%s:END]\n", "LOGIN");
                    }
                    
                }
            }
        }

	}
}

bool is_valid_ip_address(char *ip)
{
    struct sockaddr_in address;
    int valid = inet_pton(AF_INET, ip, &(address.sin_addr));
    return valid != 0;
}

bool is_valid_port(char *port)
{
    for(int i = 0; port[i]!= '\0'; i++){
		if(isdigit(port[i]) == 0){
			return false;
		}
	}
	return true;
}

int connect_server(char *ip, char *port){
	struct addrinfo address, *res;
	memset(&address, 0, sizeof address);

	address.ai_family = AF_UNSPEC;
	address.ai_socktype = SOCK_STREAM;

	getaddrinfo(ip, port, &address, &res);

	int socketfd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
	int connect_result = connect(socketfd, res->ai_addr, res->ai_addrlen);
	return socketfd;
}

char * get_ip_address(){
    struct sockaddr_in address;
    int socketfd = socket ( AF_INET, SOCK_DGRAM, 0);
    if(socketfd == -1)
    {
        perror("Socket creation failed");
    }

    memset( &address, 0, sizeof(address) );
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = inet_addr("8.8.8.8");
    address.sin_port = htons(53);
 
    int connect_result = connect(socketfd , (const struct sockaddr*) &address , sizeof(address));
    if(connect_result == -1){
		perror("Connection failure");
	}

    struct sockaddr_in actual_address;
	socklen_t socklen = sizeof(actual_address);
    int sock = getsockname(socketfd, (struct sockaddr*) &actual_address, &socklen);
         
    char ip[32];
    const char* p = inet_ntop(AF_INET, &actual_address.sin_addr, ip, 32);
	char * ip_address = malloc(strlen(ip));
	ip_address = ip;
	return ip_address;
}

char * get_port_number(){
	struct sockaddr_in actual_address;
    socklen_t socklen = sizeof(actual_address);
    int sock = getsockname(main_socketfd, (struct sockaddr*) &actual_address, &socklen);
    int port = ntohs(actual_address.sin_port);
	char port_num[6];
	sprintf(port_num, "%d", port);
	char * port_number = malloc(strlen(port_num));
	port_number = port_num;
    return port_number;
}

void call_server(char *server_port){
    // struct sockaddr_in server_address;
    struct addrinfo address, *res;
    int backlog = 5;
    // int server_socket = socket(AF_INET, SOCK_STREAM, 0);
    // if(server_socket == 0){
    //  perror("Failed to create socket");
    //  exit(-1);
    // }
    memset(&address, 0, sizeof address);
    address.ai_family = AF_UNSPEC;  // use IPv4 or IPv6, whichever
    address.ai_socktype = SOCK_STREAM;
    address.ai_flags = AI_PASSIVE;
    // printf("socket created \n");
    getaddrinfo(NULL, server_port, &address, &res);
    // server_address.sin_family = AF_INET;
    // server_address.sin_addr.s_addr = htonl(INADDR_ANY);
    // server_address.sin_port = htons(server_port);
    int socketfd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if(socketfd == -1){
        perror("Socket creation failed");
        exit(-1);
    }
    main_socketfd = socketfd;
    int result = bind(socketfd, res->ai_addr, res->ai_addrlen);
    if(result == -1){
        perror("Binding of socket failed");
        exit(-1);
    }
    
     


    // if (bind(server_socket, (struct sockaddr *)&server_address, 
    //                              sizeof(server_address))<0)
    // {
    //     perror("Failed to bind");
    //     exit(-1);
    // }
    // int yes=1;
    // if (setsockopt(socketfd,SOL_SOCKET,SO_REUSEADDR,&yes,sizeof yes) == -1) {
    // perror("setsockopt");
    // exit(1);
    // }

    if (listen(socketfd, backlog) == -1)
    {
        perror("Failed to listen");
        exit(-1);
    }

    fd_set master, read_fds;
    FD_ZERO(&master); 
    FD_ZERO(&read_fds);
    FD_SET(STDIN, &master);
    FD_SET(socketfd, &master);
    int fdmax = socketfd;
    socklen_t addrlen;
    struct sockaddr_in clientaddr; 
    int acceptedfd;
    struct message recivied_message;

    char buffer[256];    // buffer for client data
    int numberOfbytes;

    char clientIP[INET6_ADDRSTRLEN];
    
    for(int i=0;i<5;i++)
    {
        // list_array[i]=(struct host *)malloc(sizeof(struct host));
        list_array[i].id=0;
        list_array[i].queued_messages == NULL;
        list_array[i].queued_count = 0;
        list_array[i].queued_messages = (struct message *)malloc(sizeof(struct message));
        // client_block_list_ptr[i]=(struct list_content *)malloc(sizeof(struct client_block_list));
        // client_block_list_ptr[i]->C_id=0;
        // strcpy(client_block_list_ptr[i]->ip1,"null");
        // strcpy(client_block_list_ptr[i]->ip2,"null");
        // strcpy(client_block_list_ptr[i]->ip3,"null");
        // strcpy(client_block_list_ptr[i]->ip4,"null");
    }

    while(true) {
		fflush(stdout);
        read_fds = master; 
        if (select(fdmax+1, &read_fds, NULL, NULL, NULL) == -1) {
            perror("Failed to select server");
            exit(4);
        }
        for(int i = 0; i <= fdmax; i++) {
            if (FD_ISSET(i, &read_fds)) { // we got one!!
                if(STDIN == i){
                    // printf("Add author, IP, Port and stuff");
                    char *input = (char*) malloc(sizeof(char)*256);
                    memset(input, '\0', 256);
                    fgets(input, 255, stdin);
                    int length = strlen(input);
                    input[length - 1] = '\0';
                    if(strcmp(input, "AUTHOR") == 0){
                        cse4589_print_and_log("[%s:SUCCESS]\n", "AUTHOR");
                        cse4589_print_and_log("I, %s, have read and understood the course academic integrity policy.\n", "anupatul");
                        cse4589_print_and_log("[%s:END]\n", "AUTHOR");
                    }
                    else if(strcmp(input, "IP") == 0){
                        char * ip_address = get_ip_address();
                        if(ip_address){
                            cse4589_print_and_log("[%s:SUCCESS]\n", "IP");
                            cse4589_print_and_log("IP:%s\n", ip_address);
                            cse4589_print_and_log("[%s:END]\n", "IP");
                        }
                        else {
                            cse4589_print_and_log("[%s:ERROR]\n", "IP");
                            cse4589_print_and_log("[%s:END]\n", "IP");
                        }
                        
                    }
                    else if(strcmp(input, "PORT") == 0){
                        char* port = get_port_number();
                        if(port){
                            cse4589_print_and_log("[%s:SUCCESS]\n", "PORT");
                            cse4589_print_and_log("PORT:%s\n", port);
                            cse4589_print_and_log("[%s:END]\n", "PORT");
                        }
                        else {
                            cse4589_print_and_log("[%s:ERROR]\n", "PORT");
                            cse4589_print_and_log("[%s:END]\n", "PORT");
                        }
                    }
                    else if((strcmp(input, "LIST"))==0)
                    {
                        // sort_list_port();
                        // cse4589_print_and_log("[LIST:SUCCESS]\n");
                        cse4589_print_and_log("[%s:SUCCESS]\n", "LIST");
                        sort_list();
                        int g = 1;
                        for(int i=0;i<5;i++)
                        {
                            if(list_array[i].id!=0 && list_array[i].is_logged_in)
                            {   
                                cse4589_print_and_log("%-5d%-35s%-20s%-8s\n" ,g++, list_array[i].hostname, list_array[i].ip_addr, list_array[i].port_num);
                            }
                        }
                        cse4589_print_and_log("[%s:END]\n", "LIST");
                        // cse4589_print_and_log("[LIST:END]\n");
                    }
                    else if((strcmp(input, "STATISTICS"))==0)
                    {
                        cse4589_print_and_log("[%s:SUCCESS]\n", "STATISTICS");
                        sort_list();
                        for(int i=0;i<5;i++)
                        {
                            if(list_array[i].id!=0)
                            {   
                                char log_status[10];
                                if(list_array[i].is_logged_in){
                                    strcpy(log_status,"logged-in");
                                } else {
                                    strcpy(log_status,"logged-out");
                                }
                                cse4589_print_and_log("%-5d%-35s%-8d%-8d%-8s\n", list_array[i].id, list_array[i].hostname, list_array[i].num_msg_sent, list_array[i].num_msg_rcv, log_status);
                            }
                        }
                        cse4589_print_and_log("[%s:END]\n", "STATISTICS");
                        // cse4589_print_and_log("[LIST:END]\n");
                    }
                    else if((strncmp(input, "BLOCKED", 7))==0)
                    {
                        char ip[32];
                        int i = 0;
                        int j = 8;
                        while(input[j] != '\0'){
                            ip[i++] = input[j++]; 
                        }
                        ip[i] = '\0';
                        bool ipvalid = is_valid_ip_address(ip);
                        if(!ipvalid){
                            cse4589_print_and_log("[%s:ERROR]\n", "BLOCKED");
                            cse4589_print_and_log("[%s:END]\n", "BLOCKED");
                            continue;
                        }
                        bool ip_present = false;
                        for(int h=0;h<5;h++){
                            if(list_array[h].id != 0){
                                if(strcmp(ip, list_array[h].ip_addr) == 0){
                                    ip_present = true;
                                    break;
                                }
                            }
                        }
                        if(!ip_present){
                            cse4589_print_and_log("[%s:ERROR]\n", "BLOCKED");
                            cse4589_print_and_log("[%s:END]\n", "BLOCKED");
                            continue;
                        }
                        cse4589_print_and_log("[%s:SUCCESS]\n", "BLOCKED");
                        int count = -1;
                        for(int g=0; g<5;g++){
                            strcpy(blocked_list[g].hostname, "");
                            strcpy(blocked_list[g].ip, "");
                            strcpy(blocked_list[g].port, "");
                        }
                        int blocked_counter = -1;
                        for(int i=0;i<5;i++)
                        {
                            if(list_array[i].id!=0)
                            {   
                                if(strcmp(list_array[i].ip_addr, ip) == 0){
                                    for(int k=0;k<5;k++){
                                        if(strlen(list_array[i].blocked[k]) > 0){
                                            for(int x=0;x<5;x++){
                                                if(strcmp(list_array[x].ip_addr, list_array[i].blocked[k]) == 0){
                                                    ++blocked_counter;
                                                    strcpy(blocked_list[blocked_counter].hostname, list_array[x].hostname);
                                                    strcpy(blocked_list[blocked_counter].ip, list_array[x].ip_addr);
                                                    strcpy(blocked_list[blocked_counter].port, list_array[x].port_num);
                                                    // cse4589_print_and_log("%-30s%-20s%-20s\n" , list_array[x].hostname, list_array[x].ip_addr, list_array[x].port_num);
                                                    break;
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                        sort_blocked_list();
                        for(int t=0; t<=blocked_counter; t++){
                            cse4589_print_and_log("%-5d%-30s%-20s%-20s\n" , t+1, blocked_list[t].hostname, blocked_list[t].ip, blocked_list[t].port);
                        }
                        cse4589_print_and_log("[%s:END]\n", "BLOCKED");
                        // cse4589_print_and_log("[LIST:END]\n");
                    }
                    
                }
                else if (i == socketfd) {
                    // printf("Inside new connection\n");
                    // handle new connections
                    addrlen = sizeof(clientaddr); 
                    acceptedfd = accept(socketfd,
                        (struct sockaddr *)&clientaddr,
                        &addrlen);
					// printf("Port No.: %d",(int)ntohs(clientaddr.sin_port));

                    if (acceptedfd == -1) {
                        perror("Failed to accept connection");
                    } 
                    else {

                        FD_SET(acceptedfd, &master); 
                        if (acceptedfd > fdmax) {    
                            fdmax = acceptedfd;
                        }
                        char ip_addr[32];
                        strcpy(ip_addr, inet_ntop(clientaddr.sin_family,get_in_addr((struct sockaddr*)&clientaddr),clientIP, INET6_ADDRSTRLEN));
                        bool client_found = false;
                        for(int j=0;j<5;j++)
                        {
                            if(list_array[j].id != 0){
                                if(strcmp(list_array[j].ip_addr, ip_addr) == 0){
                                    list_array[j].is_logged_in = true; 
                                    // list_array[j].fd=acceptedfd;
                                    // client_found = true;
                                    // printf("Logged In again\n");
                                    // if(list_array[j].queued_messages){
                                    //     printf("Queued Message\n");
                                    //     // char* temp_message = *list_array[j].queued_messages;
                                    //     list_array[j].num_msg_rcv += 1;
                                    //     strcpy(list_array[j].queued_messages->text, "RECEIVED");
                                    //     int send_info = send(list_array[j].fd, &list_array[j].queued_messages, sizeof(list_array[j].queued_messages), 0);
                                    //     printf("send_info: %d, text: %s\n",send_info, list_array[j].queued_messages->text);
                                    // }
                                    break;
                                }
                            }
                        }
                        if (client_found){
                            continue;
                        }
                        // char client_ip[32];
						// client_ip = inet_ntop(clientaddr.sin_family,get_in_addr((struct sockaddr*)&clientaddr),clientIP, INET6_ADDRSTRLEN);
                        // printf("Accepted connection from %s on socket %d\n",inet_ntop(clientaddr.sin_family,get_in_addr((struct sockaddr*)&clientaddr),clientIP, INET6_ADDRSTRLEN),acceptedfd);
                        // printf("creating client");
                        char client[1024];
                        // printf("getnameinfo");
                        getnameinfo((struct sockaddr *)&clientaddr, addrlen,client, sizeof(client), 0,0,0);
                        // printf("client name is:-%s", client);
                        // printf("Port number is :-%d", ntohs(clientaddr.sin_port));
                        // printf("nclients");
                        // int nclients=0;
						// printf("Nclients: %d, id: %d\n",nclients, host_ptr[nclients]->id);
                        // while(host_ptr[nclients]->id!=0)
                        // {
						// 	printf("Inside while\n");
						// 	printf("%-5d%-30s%-20s%-20d\n" ,host_ptr[nclients]->id, host_ptr[nclients]->hostname, host_ptr[nclients]->ip_addr, host_ptr[nclients]->port_num);
                        //     nclients++;
                        //     printf("increased nclient: %d\n", nclients);
						// 	printf("While done");

                        // }
						int nclients = ++client_accepted;
						// printf("Nclients: %d\n",nclients);
						// printf("PORT number is: %d\n",ntohs(clientaddr.sin_port));
                        // printf("nclients");
                        list_array[nclients].id=nclients+1;
                        // strcpy(host_ptr[nclients]->id,nclients+1);
                        
                        // list_array[nclients].port_num=clientaddr.sin_port;
                        // strcpy(host_ptr[nclients]->port_num,clientaddr.sin_port);
                        list_array[nclients].fd=acceptedfd;
                        // printf("fd");
                        list_array[nclients].num_msg_sent=0;
                        // printf("snd");
                        list_array[nclients].num_msg_rcv=0;
                        // printf("rcv");
                        list_array[nclients].is_logged_in=true;
                        // strcpy(host_ptr[nclients]->is_logged_in,1);
                        // printf("%s", inet_ntop(clientaddr.sin_family,get_in_addr((struct sockaddr*)&clientaddr),clientIP, INET6_ADDRSTRLEN));
						list_array[nclients].ip_addr = malloc(32);
						strcpy(list_array[nclients].ip_addr, inet_ntop(clientaddr.sin_family,get_in_addr((struct sockaddr*)&clientaddr),clientIP, INET6_ADDRSTRLEN));
                        // list_array[nclients].ip_addr = inet_ntop(clientaddr.sin_family,get_in_addr((struct sockaddr*)&clientaddr),clientIP, INET6_ADDRSTRLEN);
                        // host_ptr[nclients]->ip_addr = malloc(32)
						// host_ptr[nclients]->ip_addr = client_ip;
                        // strcpy(host_ptr[nclients]->ip_addr,inet_ntop(clientaddr.sin_family,get_in_addr((struct sockaddr*)&clientaddr),clientIP, INET6_ADDRSTRLEN));
                        // printf("%s", client);
                        list_array[nclients].hostname = malloc(50);
                        strcpy(list_array[nclients].hostname,client);
                        // printf("name");
						// printf("%-5d%-30s%-20s%-20d\n" ,list_array[nclients].id, list_array[nclients].hostname, list_array[nclients].ip_addr, list_array[nclients].port_num);
                        // sort_list_port();
                    
                    }
                } else {
                    // handle data from a client
                    memset(&recivied_message, '\0', sizeof(recivied_message));

                    if (recv(i, &recivied_message, sizeof(recivied_message), 0) <= 0) {
                        // got error or connection closed by client
                        if (numberOfbytes == 0) {
                            // connection closed
                            printf("Connection is closed of socket %d \n", i);
                        } else {
                            // perror("Failed to receive data");
                        }
                        close(i); // bye!
                        FD_CLR(i, &master); // remove from master set
                    } else {
                        if(strcmp(recivied_message.text, "CLIENT_PORT") == 0){
                            for(int i=0;i<5;i++)
                            {
                                if(strcmp(list_array[i].ip_addr, recivied_message.from_ip_addr) == 0)
                                {   
                                    list_array[i].port_num = malloc(6);
                                    strcpy(list_array[i].port_num, recivied_message.from_port);
                                    break;
                                }
                            }
                            // printf("Inside client port \n");
                            struct refresh_list list[5];
                            for(int j=0;j<5;j++)
                            {
                                list[j].id = 0;
                            }
                            int counter = 0;
                            for(int j=0;j<5;j++)
                            {
                                if(list_array[j].id!=0  && list_array[j].is_logged_in)
                                {   
                                    // printf("Client info received %d\n",j);
                                    list[j].id = list_array[j].id;
                                    strcpy(list[j].hostname, list_array[j].hostname);
                                    strcpy(list[j].ip, list_array[j].ip_addr);
                                    strcpy(list[j].port, list_array[j].port_num);
                                    list[j].logged_in = list_array[j].is_logged_in;
                                    counter++;
                                }
                            }
                            // printf("Sending the list %d\n",sizeof(list));
                            int send_info = send(i, &list, sizeof(list), 0);
                        }
                        else if(strcmp(recivied_message.text, "REFRESH") == 0){
                            struct refresh_list list[5];
                            for(int j=0;j<5;j++)
                            {
                                list[j].id = 0;
                            }
                            int counter = 0;
                            // sort_list();
                            for(int j=0;j<5;j++)
                            {
                                if(list_array[j].id!=0 && list_array[j].is_logged_in)
                                {   
                                    
                                    list[j].id = list_array[j].id;
                                    strcpy(list[j].hostname, list_array[j].hostname);
                                    strcpy(list[j].ip, list_array[j].ip_addr);
                                    strcpy(list[j].port, list_array[j].port_num);
                                    list[j].logged_in = list_array[j].is_logged_in;
                                    // printf("IP: %s\n", list[counter].ip);
                                    counter++;
                                }
                            }
                            int send_info = send(i, &list, sizeof(list), 0);
                            // printf("Sendinfo: %d\n",send_info);
                        }
                        else if(strcmp(recivied_message.text, "SEND") == 0){
                            char to_ip[32];
                            char from_ip[32];
                            char msg[sizeof(recivied_message.msg)];
                            strcpy(to_ip, recivied_message.to_ip_addr);
                            strcpy(from_ip, recivied_message.from_ip_addr);
                            strcpy(msg,recivied_message.msg);
                            int to_socket_fd;
                            bool blocked = false;
                            for(int j=0;j<5;j++){
                                if(list_array[j].id != 0){
                                    if(strcmp(list_array[j].ip_addr, to_ip) == 0){
                                        for(int k=0; k<5; k++){
                                            if(strcmp(from_ip, list_array[j].blocked[k]) == 0){
                                                blocked = true;
                                            }
                                        }
                                        to_socket_fd = list_array[j].fd;
                                        if(!blocked){
                                            if(list_array[j].is_logged_in){
                                                list_array[j].num_msg_rcv += 1;
                                                cse4589_print_and_log("[%s:SUCCESS]\n", "RELAYED");
                                                cse4589_print_and_log("msg from:%s, to:%s\n[msg]:%s\n", from_ip, to_ip, msg);
                                                cse4589_print_and_log("[%s:END]\n", "RELAYED");
                                                strcpy(recivied_message.text, "RECEIVED");
                                                int send_info = send(to_socket_fd, &recivied_message, sizeof(recivied_message), 0);
                                            } else{
                                                struct message temp_buf;
                                                temp_buf.next_message = NULL;
                                                struct message *temp_ptr;
                                                temp_ptr = (struct message *)malloc(sizeof(struct message));
                                                strcpy(temp_buf.from_ip_addr, recivied_message.from_ip_addr);
                                                strcpy(temp_buf.msg, recivied_message.msg);
                                                // list_array[j].queued_messages = (struct message *)malloc(sizeof(struct message));
                                                // temp_ptr = &list_array[j].queued_messages;
                                                if(list_array[j].queued_count != 0){
                                                    // printf("Not first message\n");
                                                    
                                                    temp_ptr = list_array[j].queued_messages;
                                                    // printf("list_array[j].queued_messages: %s",list_array[j].queued_messages->msg);
                                                    int h=0;
                                                    while(h<list_array[j].queued_count-1){
                                                        // printf("Inside While\n");
                                                        // char tmsg[256];
                                                        temp_ptr = temp_ptr->next_message;
                                                        // printf("Before\n");
                                                        // strcpy(tmsg, temp_ptr->msg);
                                                        // printf("TMSG: %s\n",tmsg);
                                                        h++;
                                                    }
                                                    temp_ptr->next_message->next_message = (struct message *)malloc(sizeof(struct message));
                                                    // temp_ptr->next_message = &temp_buf;
                                                    strcpy(temp_ptr->next_message->from_ip_addr, temp_buf.from_ip_addr);
                                                    strcpy(temp_ptr->next_message->msg, temp_buf.msg);
                                                    // printf("First Msg - IP: %s, Msg: %s",temp_ptr->next_message->from_ip_addr, temp_ptr->next_message->msg);
                                                    list_array[j].queued_count++;
                                                    // printf("value: %s\n", temp_ptr->next_message->next_message);
                                                } else {
                                                    // printf("First Message\n");
                                                    // temp_ptr = list_array[j].queued_messages;
                                                    strcpy(list_array[j].queued_messages->from_ip_addr, temp_buf.from_ip_addr);
                                                    strcpy(list_array[j].queued_messages->msg, temp_buf.msg);
                                                    list_array[j].queued_messages->next_message = (struct message *)malloc(sizeof(struct message));

                                                    list_array[j].queued_count++;
                                                    // printf("First Msg - IP: %s, Msg: %s",list_array[i].queued_messages->from_ip_addr, list_array[i].queued_messages->msg);

                                                }
                                                // list_array[j].queued_messages = &temp_buf;
                                                
                                                // list_array[j].queued_messages->from_ip_addr = recivied_message.from_ip_addr;
                                                // list_array[j].queued_messages->msg = recivied_message.msg;
                                            }
                                        }
                                    }
                                    if(strcmp(list_array[j].ip_addr, from_ip) == 0){
                                        list_array[j].num_msg_sent += 1; 
                                    }
                                }
                            }
                            if(!blocked){
                                // cse4589_print_and_log("[%s:SUCCESS]\n", "RELAYED");
                                // cse4589_print_and_log("msg from:%s, to:%s\n[msg]:%s\n", from_ip, to_ip, msg);
                                // cse4589_print_and_log("[%s:END]\n", "RELAYED");
                                // strcpy(recivied_message.text, "RECEIVED");
                                // int send_info = send(to_socket_fd, &recivied_message, sizeof(recivied_message), 0);
                            }
                        }
                        else if(strcmp(recivied_message.text, "LOGOUT") == 0){
                            char from_ip[32];
                            strcpy(from_ip, recivied_message.from_ip_addr);
                            for(int j=0;j<5;j++){
                                if(list_array[j].id != 0){
                                    if(strcmp(list_array[j].ip_addr, from_ip) == 0){
                                        list_array[j].is_logged_in = false; 
                                    }
                                }
                            }
                        }
                        else if(strcmp(recivied_message.text, "EXIT") == 0){
                            char from_ip[32];
                            strcpy(from_ip, recivied_message.from_ip_addr);
                            for(int j=0;j<5;j++){
                                if(list_array[j].id != 0){
                                    if(strcmp(list_array[j].ip_addr, from_ip) == 0){
                                        list_array[j].id = 0;
                                        break;
                                    }
                                }
                            }
                        }
                        else if(strcmp(recivied_message.text, "BROADCAST") == 0){
                            char from_ip[32];
                            char msg[sizeof(recivied_message.msg)];
                            strcpy(from_ip, recivied_message.from_ip_addr);
                            strcpy(msg,recivied_message.msg);
                            int to_socket_fd;
                            strcpy(recivied_message.text, "RECEIVED");
                            // bool blocked = false;
                            for(int j=0;j<5;j++){
                                bool blocked = false;
                                if(list_array[j].id != 0){
                                    if(strcmp(list_array[j].ip_addr, from_ip) == 0){
                                        list_array[j].num_msg_sent += 1; 
                                        continue;
                                    }
                                    for(int k=0; k<5; k++){
                                        if(strcmp(from_ip, list_array[j].blocked[k]) == 0){
                                            blocked = true;
                                            break;
                                        }
                                    }
                                    if(!blocked){
                                        list_array[j].num_msg_rcv += 1;
                                        to_socket_fd = list_array[j].fd;
                                        int send_info = send(to_socket_fd, &recivied_message, sizeof(recivied_message), 0);
                                    }
                                }
                            }
                            cse4589_print_and_log("[%s:SUCCESS]\n", "RELAYED");
                            cse4589_print_and_log("msg from:%s, to:%s\n[msg]:%s\n", from_ip, "255.255.255.255", msg);
                            cse4589_print_and_log("[%s:END]\n", "RELAYED");
                            
                            int send_info = send(to_socket_fd, &recivied_message, sizeof(recivied_message), 0);
                        }
                        else if(strcmp(recivied_message.text, "BLOCK") == 0){
                            char to_ip[32];
                            char from_ip[32];
                            strcpy(to_ip, recivied_message.to_ip_addr);
                            strcpy(from_ip, recivied_message.from_ip_addr);
                            for(int j=0;j<5;j++){
                                if(list_array[j].id != 0){
                                    if(strcmp(list_array[j].ip_addr, from_ip) == 0){
                                        for(int k=0; k<5; k++){
                                            if(strlen(list_array[j].blocked[k]) == 0){
                                                strcpy(list_array[j].blocked[k], to_ip);
                                                break;
                                            }
                                        }
                                    }
                                }
                            }
                        }
                        else if(strcmp(recivied_message.text, "UNBLOCK") == 0){
                            char to_ip[32];
                            char from_ip[32];
                            strcpy(to_ip, recivied_message.to_ip_addr);
                            strcpy(from_ip, recivied_message.from_ip_addr);
                            for(int j=0;j<5;j++){
                                if(list_array[j].id != 0){
                                    if(strcmp(list_array[j].ip_addr, from_ip) == 0){
                                        for(int k=0; k<5; k++){
                                            if(strcmp(list_array[j].blocked[k], to_ip) == 0){
                                                strcpy(list_array[j].blocked[k], "");
                                                break;
                                            }
                                        }
                                    }
                                }
                            }
                        }
                        else if(strcmp(recivied_message.text, "RELOGIN") == 0){
                            // printf("Inside Relogin\n");
                            for(int i=0;i<5;i++)
                            {
                                if(strcmp(list_array[i].ip_addr, recivied_message.from_ip_addr) == 0)
                                {   
                                    list_array[i].is_logged_in = true;
                                    struct refresh_list list[5];
                                    for(int j=0;j<5;j++)
                                    {
                                        list[j].id = 0;
                                    }
                                    int counter = 0;
                                    for(int j=0;j<5;j++)
                                    {
                                        if(list_array[j].id!=0  && list_array[j].is_logged_in)
                                        {   
                                            // printf("Client info received %d\n",j);
                                            list[counter].id = list_array[j].id;
                                            strcpy(list[counter].hostname, list_array[j].hostname);
                                            strcpy(list[counter].ip, list_array[j].ip_addr);
                                            strcpy(list[counter].port, list_array[j].port_num);
                                            counter++;
                                        }
                                    }
                                    // printf("Sending the list %d\n",sizeof(list));
                                    int send_info = send(list_array[i].fd, &list, sizeof(list), 0);
                                    // printf("Logged In again\n");
                                    if(list_array[i].queued_count != 0){
                                        // printf("Queued Message\n");
                                        // char* temp_message = *list_array[j].queued_messages;
                                        list_array[i].num_msg_rcv += 1;
                                        struct message temp;
                                        strcpy(temp.text, "RECEIVED");
                                        strcpy(temp.from_ip_addr, list_array[i].queued_messages->from_ip_addr);
                                        strcpy(temp.msg, list_array[i].queued_messages->msg);
                                        cse4589_print_and_log("[%s:SUCCESS]\n", "RELAYED");
                                        cse4589_print_and_log("msg from:%s, to:%s\n[msg]:%s\n", temp.from_ip_addr, list_array[i].ip_addr, temp.msg);
                                        cse4589_print_and_log("[%s:END]\n", "RELAYED");
                                        // printf("First Msg - IP: %s, Msg: %s",list_array[i].queued_messages->from_ip_addr, list_array[i].queued_messages->msg);
                                        int send_info = send(list_array[i].fd, &temp, sizeof(temp), 0);
                                        struct message *temp_ptr;
                                        // temp_ptr = (struct message *)malloc(sizeof(struct message));
                                        temp_ptr = list_array[i].queued_messages;
                                        int h = 1;
                                        while(h < list_array[i].queued_count){
                                            temp_ptr = temp_ptr->next_message;
                                            // printf("Inside while for multiple messafe\n");
                                            list_array[i].num_msg_rcv += 1;
                                            strcpy(temp.text, "RECEIVED");
                                            strcpy(temp.from_ip_addr, temp_ptr->from_ip_addr);
                                            strcpy(temp.msg, temp_ptr->msg);
                                            // printf("While - IP: %s, Msg: %s",temp_ptr->from_ip_addr, temp_ptr->msg);
                                            cse4589_print_and_log("[%s:SUCCESS]\n", "RELAYED");
                                            cse4589_print_and_log("msg from:%s, to:%s\n[msg]:%s\n", temp.from_ip_addr, list_array[i].ip_addr, temp.msg);
                                            cse4589_print_and_log("[%s:END]\n", "RELAYED");
                                            int send_info = send(list_array[i].fd, &temp, sizeof(temp), 0);
                                            h++;
                                        }
                                        // printf("IP Address: %s, Msg: %s\n", list_array[i].queued_messages->from_ip_addr, list_array[i].queued_messages->msg);
                                        // strcpy(list_array[i].queued_messages->text, "RECEIVED");
                                        // int send_info = send(list_array[i].fd, &list_array[i].queued_messages, sizeof(list_array[i].queued_messages), 0);
                                        
                                        list_array[i].queued_messages = (struct message *)malloc(sizeof(struct message));
                                        list_array[i].queued_count = 0;
                                        strcpy(temp.text, "Buffer Completed");
                                        send_info = send(list_array[i].fd, &temp, sizeof(temp), 0);
                                        break;
                                        // printf("send_info: %d, text: %s size:%d\n",send_info, list_array[i].queued_messages->text,sizeof(list_array[i].queued_messages));
                                    }
                                    
                                }
                            }
                            // printf("Inside client port \n");
                            
                        }
                        // we got some data from a client
                        // for(int j = 0; j <= fdmax; j++) {
                        //     // send to everyone!
                        //     if (FD_ISSET(j, &master)) {
                        //         // except the listener and ourselves
                        //         if (j != socketfd && j != i) {
                        //             if (send(j, buffer, numberOfbytes, 0) == -1) {
                        //                 perror("Failed to send data");
                        //             }
                        //         }
                        //     }
                        // }
                    }
                } // END handle data from client
            } // END got new incoming connection
        } // END looping through file descriptors
    }

    // int addrlen = sizeof(address);
    // int new_socket = accept(socketfd, (struct addrinfo *)&address, 
    //                    (socklen_t*)&addrlen);
    // if(new_socket == -1)
    // {
    //     perror("Failed to accept the connection");
    //     exit(-1);
    // }

}


void *get_in_addr(struct sockaddr *sa)
{
	if (sa->sa_family == AF_INET) {
		return &(((struct sockaddr_in*)sa)->sin_addr);
	}

	return &(((struct sockaddr_in6*)sa)->sin6_addr);
}

void sort_list(){
    int i,j;
    for(i=0;i<5;i++){
        for(j=0;j<5-i-1;j++){
            if(list_array[j].id!=0 && list_array[j+1].id!=0){
                int port1 = atoi(list_array[j].port_num);
                int port2 = atoi(list_array[j+1].port_num);
                if(port1 > port2){
                    struct host temp;               
                    temp = list_array[j];
                    list_array[j] = list_array[j+1];
                    list_array[j+1] = temp;
                }
            }
        }
    }
}

void sort_blocked_list(){
    int i,j;
    for(i=0;i<5;i++){
        for(j=0;j<5-i-1;j++){
            if(strlen(blocked_list[j].ip)!=0 && strlen(blocked_list[j+1].ip)!=0){
                int port1 = atoi(blocked_list[j].port);
                int port2 = atoi(blocked_list[j+1].port);
                if(port1 > port2){
                    struct blocked temp;               
                    temp = blocked_list[j];
                    blocked_list[j] = blocked_list[j+1];
                    blocked_list[j+1] = temp;
                }
            }
        }
    }
}
