/**
 * @sa32_assignment1
 * @author  Shailesh Adhikari <sa32@buffalo.edu>
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

#include<string.h>
#include<ctype.h>

#include<sys/types.h>
#include<sys/socket.h>
#include<netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

#include "../include/global.h"
#include "../include/logger.h"

#include <strings.h>
#include <unistd.h>

#define BACKLOG 5
#define STDIN 0
#define TRUE 1
#define CMD_SIZE 100
#define BUFFER_SIZE 256
#define MSG_SIZE 256
#define SERVER_TYPE 0
#define CLIENT_TYPE 1

#define SUCCESS 0
#define FAIL 1

#define LOGGED_IN 0
#define LOGGED_OUT 1

/**
 * main function
 *
 * @param  argc Number of arguments
 * @param  argv The argument list
 * @return 0 EXIT_SUCCESS
 */


void client_call(int port_number);
void server_call(int port_number);

void get_login_attributes(char* cmd, char *cmd_header, char *server_ip_address, char *server_port_number);
void get_send_cmd_attributes(char* cmd, char *cmd_header, char *ip_and_msg);
void get_block_cmd_attributes(char* cmd, char *cmd_header, char *server_ip_address);
char* generate_msg_from_client_list();
int sendall(int socket_fd, char *buf, int *len);
int login_to_server(char *server_ip, int server_port);
char* get_IP_address();
int get_port_on_login(char* login_msg);
void get_ip_from_message(char *msg, char *IP, int remove_ip_frm_msg);
int get_socketfd_by_ip(char *ip);
void string_concat(char **str, const char *str2);
void insert_client_node(int port_number, int socket_fd);
void remove_client_node(int socket_index);
void print_client_nodes();
void execute_author_command(char* command_str, int type);
void execute_login_command(char* command_str, int status);
void execute_IP_command(char* command_str, int type);
void execute_port_command(char *command_str, int type, int port_number);
void execute_list_command(char* command_str, int type);
void execute_refresh_command(char* command_str);
void execute_block_command(char* command_str, int status);
void execute_unblock_command(char* command_str, int status);
void execute_blocked_command(char* command_str, int status);
void execute_exit_command(char* command_str);

struct client_node* root_node;

int log_status = LOGGED_IN;

char c_blocked_clients[300];

struct client_node{
	int socket_fd;
	int port_number;
	int logging_status;
	int msg_sent;
	int msg_received;
	char ip_address[64];
	char host_name[64];
	char blocked_clients[300];
	struct client_node *next;
};


int main(int arg1, char **arg2){
	
	if(arg1 != 3) {
		//printf("Usage:%s [port]\n", arg2[0]);
		exit(-1);
	}
	
		/*Init. Logger*/
	cse4589_init_log(arg2[2]);

	/*Clear LOGFILE*/
	fclose(fopen(LOGFILE, "w"));
	
	/**printf("1 : %s \n", arg2[1]);
	printf("2 : %s\n", arg2[2]);**/
	
	if(strcmp(arg2[1],"")==0 || strcmp(arg2[2],"")==0){
		printf("Two inputs required : server/client and port number\n");
		return  0;
	}
	
	// deligating server and client calls
	if(strcmp(arg2[1],"c") == 0)
		client_call(atoi(arg2[2]));
	else if(strcmp(arg2[1],"s") == 0)
		server_call(atoi(arg2[2]));
	
	return 0;
	
}

void client_call(int port_number){
	printf("Making client call.");	
	//char server_ip[20] = "192.168.152.133";
	
	int client_socket, head_socket;
	int select_result, fdaccept=0, caddr_len;
	struct sockaddr_in client_addr, server_addr;
	fd_set master_list, watch_list;

	//Creating client socket for listening
	client_socket = socket(AF_INET, SOCK_STREAM, 0);
    if(client_socket < 0)
		perror("Cannot create client socket");

	// Specifying client address
	bzero(&client_addr, sizeof(client_addr));

    client_addr.sin_family = AF_INET;
    client_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    client_addr.sin_port = htons(port_number);

    //Resetting the master and watch list sets
    FD_ZERO(&master_list);
    FD_ZERO(&watch_list);
    
    //Adding the client socket to master list set
    //FD_SET(client_socket, &master_list);
    /* Register STDIN */
    FD_SET(STDIN, &master_list);

    head_socket = STDIN;

    while(TRUE){
        memcpy(&watch_list, &master_list, sizeof(master_list));
        
        int max_fd = head_socket;

        //printf("\n[PA1-Server@CSE489/589]$ ");
		//fflush(stdout);

       // Select call for server - This will block
        select_result = select(head_socket + 1, &watch_list, NULL, NULL, NULL);
        if(select_result < 0)
            perror("select failed.");

        // Check if we have sockets/STDIN to process 
        if(select_result > 0){
            // Loop through socket descriptors to check which ones are ready 
            for(int socket_index=0; socket_index<=max_fd; socket_index+=1){

            	if(FD_ISSET(socket_index, &watch_list)){

                    // Check if new command on STDIN 
                    if (socket_index == STDIN){
						char cmd[CMD_SIZE];
						if(fgets(cmd, CMD_SIZE-1, stdin) == NULL) //Mind the newline character that will be written to cmd
							exit(-1);
						
						//strtok(cmd, "\n");
					
						printf("client_call , command registered : %s, : %d", cmd, strlen(cmd));
						
						if(strncmp(cmd,"AUTHOR", 6)==0)
							execute_author_command(cmd, CLIENT_TYPE);
						else if(strncmp(cmd, "LOGIN", 5)==0){
						
							char cmd_header[10]; 
							char server_ip_address[20];
							char server_port_number[10];
							get_login_attributes(cmd, cmd_header, server_ip_address, server_port_number);
							printf("cmd_header : %s, ip : %s, port : %s, port length", 
									cmd_header, server_ip_address, server_port_number, strlen(server_port_number));
									
							if(is_valid_ip_address(server_ip_address) > 0 && is_valid_port_number(server_port_number) > 0){
								if(log_status==LOGGED_IN){
									client_socket = login_to_server(server_ip_address, atoi(server_port_number));
									if(client_socket != -1){
										char login_header[16] = "login_info~";
										char port_number_str[5];
										sprintf(port_number_str, "%d", port_number);
										strcat(login_header, port_number_str);
										int login_header_len = strlen(login_header);
										//send(client_socket, login_header, login_header_len, 0);
										if (sendall(client_socket, login_header, &login_header_len) == -1) 
											printf("Client side send error, msg : \n", login_header_len);

										FD_SET(client_socket, &master_list);
	                        			if(client_socket > head_socket) head_socket = client_socket;
									}
								}
								else if(log_status==LOGGED_OUT){
									char login_header[16] = "logged_in~";
									log_status==LOGGED_IN;
									int login_header_len = strlen(login_header);
									//send(client_socket, login_header, login_header_len, 0);
									if (sendall(client_socket, login_header, &login_header_len) == -1) {
										//perror("sendall");
										printf("Client side send error, msg : \n", login_header_len);
									}
								}
								execute_login_command(cmd_header, SUCCESS);
							}
							else
								execute_login_command(cmd_header, FAIL);
								
							memset(cmd_header, 0, 10);
							memset(server_ip_address, 0, 20);
							memset(server_port_number, 0, 10);
							
						}
						else if(strncmp(cmd, "IP", 2)==0)
							execute_IP_command(cmd, CLIENT_TYPE);
						else if(strncmp(cmd, "PORT", 4)==0)
							execute_port_command(cmd, CLIENT_TYPE, port_number);
						else if(strncmp(cmd, "LIST", 4)==0 && log_status==LOGGED_IN)
							execute_list_command(cmd, CLIENT_TYPE);
						else if(strncmp(cmd, "SEND", 4)==0 && log_status==LOGGED_IN){
							char cmd_header[10]; 
							char ip_and_msg[308];
							char ip_address[64];
							get_send_cmd_attributes(cmd, cmd_header, ip_and_msg);
							int msg_len = strlen(ip_and_msg);
							get_ip_from_message(ip_and_msg, ip_address, 0);
							printf("Client side msg : %s\n",ip_and_msg);
							printf("is valid ip : %d, exists : %d", is_valid_ip_address(ip_address), does_ip_exists_in_list(ip_address));
							if(is_valid_ip_address(ip_address) >0 && does_ip_exists_in_list(ip_address)>0){
								
								if (sendall(client_socket, ip_and_msg, &msg_len) == -1) {
									//perror("sendall");
									printf("Client side send error, msg : \n", msg_len);
								}
								execute_send_command(cmd, SUCCESS);
							}
							else
								execute_send_command(cmd, FAIL);
								
							memset(cmd_header, 0, 10);
							memset(ip_and_msg, 0, 308);
							memset(ip_address, 0, 64);
								
						}
						else if(strncmp(cmd, "BROADCAST", 9)==0 && log_status==LOGGED_IN){
							char cmd_header[10]; 
							char msg[256];
							get_send_cmd_attributes(cmd, cmd_header, msg);
							int msg_len = strlen(msg);
							char broadcast_header[308] ="broadcast~";
							strcat(broadcast_header, msg);
							/**string_concat(&broadcast_header, "broadcast~");
							string_concat(&broadcast_header, msg);**/
							int broadcast_header_len = strlen(broadcast_header);
							printf("msg to be brodacasted : %s\n", broadcast_header);
							
							if (sendall(client_socket, broadcast_header, &broadcast_header_len) == -1) 
								printf("Client side send error, msg : \n", broadcast_header_len);
							
							execute_broadcast_command(cmd);
								
							memset(cmd_header, 0, 10);
							memset(msg, 0, 256);
								
						}
						else if(strncmp(cmd, "REFRESH", 7)==0 && log_status==LOGGED_IN){
								char refresh_msg[16] = "refresh_list~";
								int refresh_msg_len = strlen(refresh_msg);
								if (sendall(client_socket, refresh_msg, &refresh_msg_len) == -1) {
									//perror("sendall");
									printf("Client side send error, msg : \n", refresh_msg_len);
								}
								execute_refresh_command(cmd);
								
							}
						else if(strncmp(cmd, "BLOCK", 5)==0 && log_status==LOGGED_IN){
							char cmd_header[10]; 
							char server_ip_address[32];
							get_block_cmd_attributes(cmd, cmd_header, server_ip_address);
							if(is_valid_ip_address(server_ip_address) >0 && does_ip_exists_in_list(server_ip_address)>0){
								/**char logged_out_msg[16] = "blocked~";
								int logged_out_msg_len = strlen(logged_out_msg);
								if (sendall(client_socket, logged_out_msg, &logged_out_msg_len) == -1) {
									//perror("sendall");
									printf("Client side send error, msg : \n", logged_out_msg_len);
								}**/
						
								execute_block_command(cmd, SUCCESS);
							}
							else
								execute_block_command(cmd, FAIL);
							
							memset(cmd_header, 0, 10);
							memset(server_ip_address, 0, 32);
							
						}
						else if(strncmp(cmd, "UNBLOCK", 5)==0 && log_status==LOGGED_IN){
							char cmd_header[10]; 
							char server_ip_address[32];
							get_block_cmd_attributes(cmd, cmd_header, server_ip_address);
							if(is_valid_ip_address(server_ip_address) >0 && does_ip_exists_in_list(server_ip_address)>0){
								/**char logged_out_msg[16] = "blocked~";
								int logged_out_msg_len = strlen(logged_out_msg);
								if (sendall(client_socket, logged_out_msg, &logged_out_msg_len) == -1) {
									//perror("sendall");
									printf("Client side send error, msg : \n", logged_out_msg_len);
								}**/
						
								execute_unblock_command(cmd, SUCCESS);
							}
							else
								execute_unblock_command(cmd, FAIL);
							
							memset(cmd_header, 0, 10);
							memset(server_ip_address, 0, 32);
							
						}
						else if(strncmp(cmd, "LOGOUT", 6)==0 && log_status==LOGGED_IN){
							char logged_out_msg[16] = "logged_out~";
							int logged_out_msg_len = strlen(logged_out_msg);
							if (sendall(client_socket, logged_out_msg, &logged_out_msg_len) == -1) {
								//perror("sendall");
								printf("Client side send error, msg : \n", logged_out_msg_len);
							}
							log_status = LOGGED_OUT;
							execute_logout_command(cmd);
							
						}
						else if(strncmp(cmd, "EXIT", 4)==0){
								char exit_msg[16] = "adios~";
								int exit_msg_len = strlen(exit_msg);
								if (sendall(client_socket, exit_msg, &exit_msg_len) == -1) {
									//perror("sendall");
									printf("Client side send error, msg : \n", exit_msg_len);
								}
								execute_exit_command(cmd);
								exit(0);
							}	
							
						printf("\n");
	                }
	                else if(socket_index == client_socket){//Reading message from the server
	                    // Initialize buffer to receieve response 
	                    char *buffer = (char*) malloc(sizeof(char)*BUFFER_SIZE);
		                memset(buffer, '\0', BUFFER_SIZE);                        
		                //char command[200];                        
						int j,i;
						printf("In else******************** , %s\n", buffer);
						if (FD_ISSET(i, &master_list)) 		
							printf(" master_list : %d\n", i);
						if (FD_ISSET(i, &watch_list)) 		
							printf(" watch_list : %d\n", i);
		                if(( j = recv(socket_index, buffer, BUFFER_SIZE, 0)) > 0){
		                	
		                	//Process incoming data from existing clients here ...
		                	
		                	printf("\Server sent me: \n%s \n >> at my socket %d\n", buffer, socket_index);
		                	
		                	//Genrating nodes from client_list_data sent by server at login
		                	if(strncmp(buffer, "list_data~", 10)==0 || strncmp(buffer, "login_info~", 11)==0){
		                		//printf("\Getting list from server at login : %s\n", buffer);
		                		generate_client_list_from_msg(buffer);
		                	}
							else{ // Chat message receiving part
								//char client_ip[64];
								
								char *ip_less_msg=NULL;
								char *client_ip = strtok(buffer, " ");
								ip_less_msg =  strtok(NULL, "");
									
								printf("\receving ip_less_msg ip : %s\n",ip_less_msg); 
								printf("\receving client_ip : %s\n",ip_less_msg); 
								execute_receive_command(client_ip, ip_less_msg);
							}
							//printf("ECHOing it back to the remote host ... ");							
							//int port_on_login = get_port_on_login(buffer);
							fflush(stdout);
		                }
	                	free(buffer);
	                }
		        }
            }
        }
    }
}


void server_call(int port_number){
	printf("Making server call.\n");	

	int server_socket, head_socket;
	int select_result, fdaccept=0, caddr_len;
	struct sockaddr_in server_addr, client_addr;
	fd_set master_list, watch_list;

	//Creating server socket for listening
	server_socket = socket(AF_INET, SOCK_STREAM, 0);
    if(server_socket < 0)
		perror("Cannot create socket");

	// Specifying server address
	bzero(&server_addr, sizeof(server_addr));

    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    server_addr.sin_port = htons(port_number);

    //Binding the server socket with specified address
    if(bind(server_socket, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0 )
    	perror("Bind failed");

    // Starting the listening process of server
    if(listen(server_socket, BACKLOG) < 0)
    	perror("Unable to listen on port");

    /* ---------------------------------------------------------------------------- */

    //Resetting the master and watch list sets
    FD_ZERO(&master_list);
    FD_ZERO(&watch_list);
    
    //Adding the server socket to master list set
    FD_SET(server_socket, &master_list);
    /* Register STDIN */
    FD_SET(STDIN, &master_list);

    head_socket = server_socket;

    while(TRUE){
        memcpy(&watch_list, &master_list, sizeof(master_list));

        //printf("\n[PA1-Server@CSE489/589]$ ");
		//fflush(stdout);

       // Select call for server - This will block
        select_result = select(head_socket + 1, &watch_list, NULL, NULL, NULL);
        if(select_result < 0)
            perror("select failed.");

        /* Check if we have sockets/STDIN to process */
        if(select_result > 0){
            /* Loop through socket descriptors to check which ones are ready */
            for(int socket_index=0; socket_index<=head_socket; socket_index+=1){

                if(FD_ISSET(socket_index, &watch_list)){

                    /* Check if new command on STDIN */
                    if (socket_index == STDIN){
						char cmd[CMD_SIZE];
						if(fgets(cmd, CMD_SIZE-1, stdin) == NULL) //Mind the newline character that will be written to cmd
							exit(-1);
						
						strtok(cmd, "\n ");
						
						if(strncmp(cmd,"AUTHOR", 6)==0)
								execute_author_command(cmd, SERVER_TYPE);
						else if(strncmp(cmd, "IP", 2)==0)
							execute_IP_command(cmd, SERVER_TYPE);
						else if(strncmp(cmd, "PORT", 4)==0)
							execute_port_command(cmd, SERVER_TYPE, port_number);
						else if(strncmp(cmd, "LIST", 4)==0)
							execute_list_command(cmd, SERVER_TYPE);
						else if(strncmp(cmd, "STATISTICS", 10)==0)
							execute_statistics_command(cmd);
						else if(strncmp(cmd, "BLOCKED", 7)==0){
							char cmd_header[10]; 
							char server_ip_address[32];
							get_block_cmd_attributes(cmd, cmd_header, server_ip_address);
							if(is_valid_ip_address(server_ip_address) >0 && does_ip_exists_in_list(server_ip_address)>0){
								/**char logged_out_msg[16] = "blocked~";
								int logged_out_msg_len = strlen(logged_out_msg);
								if (sendall(client_socket, logged_out_msg, &logged_out_msg_len) == -1) {
									//perror("sendall");
									printf("Client side send error, msg : \n", logged_out_msg_len);
								}**/
						
								execute_blocked_command(cmd, SUCCESS);
							}
							else
								execute_blocked_command(cmd, FAIL);
							
							memset(cmd_header, 0, 10);
							memset(server_ip_address, 0, 32);
						}
						printf("\n");						
                    }
                    /* Check if new client is requesting connection */
                    else if(socket_index == server_socket){
                        caddr_len = sizeof(client_addr);
                        fdaccept = accept(server_socket, (struct sockaddr *)&client_addr, &caddr_len);
                        if(fdaccept < 0)
                            perror("Accept failed.");

						printf("\nRemote Host connected!\n");                        

                        /* Add to watched socket list */
                        FD_SET(fdaccept, &master_list);
                        if(fdaccept > head_socket) head_socket = fdaccept;
                    }
                    /* Read from existing clients */
                    else{
                        /* Initialize buffer to receieve response */
                        char *buffer = (char*) malloc(sizeof(char)*BUFFER_SIZE);
                        memset(buffer, '\0', BUFFER_SIZE);

                        if(recv(socket_index, buffer, BUFFER_SIZE, 0) <= 0){
                            close(socket_index);
                            printf("Remote Host terminated connection!\n");

                            /* Remove from watched list */
                            FD_CLR(socket_index, &master_list);
                            
                            //free(buffer);
                        }
                        else {
                        	//Process incoming data from existing clients here ...

                        	printf("\nClient sent me: %s\n\n", buffer);
								
							int port_on_login = -1;
							if(strncmp(buffer, "login_info", 10)==0)
								port_on_login = get_port_on_login(buffer);
								
							//printf("port_on_login : %d  ", port_on_login);
								
							if(port_on_login != -1){
								
								/**printf("ECHOing it back to the remote host ... ");
								if(send(fdaccept, buffer, strlen(buffer), 0) == strlen(buffer))
									printf("Done!\n");**/
								
								//Insert new client node on login
								insert_client_node(port_on_login, fdaccept);
							    //printf("port_on_login : %d  ", port_on_login);
							    
							    memset(buffer, '\0', BUFFER_SIZE);

								//Converting node data into list
							    char *list_data = generate_msg_from_client_list();
							    
								//Sending list data on login back to client
								int list_data_len = strlen(list_data);
								//printf(">>>>>>>>  List data sent on login : %s\n", list_data);
								if (sendall(fdaccept, list_data, &list_data_len) == -1) {
									printf("Client side send error, msg : \n", list_data_len);
								}	
							 }
							 else{ // Receiving message from logged in user
								int buffer_len = strlen(buffer);
								
								/** Code for refresh command receive at server
								**/
								if(strncmp(buffer, "refresh_list~", 13)==0){ 
									//Converting node data into list
							   		char *list_data = generate_msg_from_client_list();
							    
									//Sending list data on refresh back to client
									int list_data_len = strlen(list_data);
									//printf(">>>>>>>>  List data sent on refresh : %s\n", list_data);
									//printf(">>>>>>>>  Sending to : %d\n", socket_index);
									if (sendall(socket_index, list_data, &list_data_len) == -1) {
										printf("Client side send error, msg : \n", list_data_len);
									}
								}
								/** Code for exit command receive at server
								**/
								else if(strncmp(buffer, "adios~", 6)==0){ 
									//Remove client node from client linked list
									remove_client_node(socket_index);
									//printf("Removing cllient node at socket fd : "+socket_index);
								}
								/** Code for log out at server
								**/
								else if(strncmp(buffer, "logged_out~", 11)==0){ 
									//Remove client node from client linked list
									log_client_node(socket_index, LOGGED_OUT);
									print_client_nodes();
									//printf("Removing cllient node at socket fd : "+socket_index);
								}/** Code for log in BACK at server
								**/
								else if(strncmp(buffer, "logged_in~", 10)==0){ 
									//Remove client node from client linked list
									log_client_node(socket_index, LOGGED_IN);
									print_client_nodes();
									//printf("Removing cllient node at socket fd : "+socket_index);
								}
								/** Code for broadcasting
								**/
								else if(strncmp(buffer, "broadcast~", 10)==0){ 
									broadcast_to_logged_in_clients(socket_index, buffer);
									//print_client_nodes();
								}
								/** Code for chat messages
								**/
								else{
									char receivers_ip[64];
									char senders_ip[64];
									get_ip_by_socketfd(socket_index, senders_ip);
									get_ip_from_message(buffer, receivers_ip, 1);
									int receivers_sock_fd = get_socketfd_by_ip(receivers_ip);
									
									char ip_less_msg[308];
									
									strcpy(ip_less_msg, buffer);
									strtok(buffer, " ");
									strcpy(receivers_ip, buffer);
									char *split =strtok(NULL, "");
									strcpy(ip_less_msg, split);
									
									printf("Buffer 1 : %s : \n",  buffer);
									
									memset(buffer, '\0', BUFFER_SIZE);
									
									string_concat(&buffer,senders_ip);
									string_concat(&buffer," ");
									string_concat(&buffer,ip_less_msg);
									
									printf("senders_ip : %s : \n",  senders_ip);
									printf("ip_less_msg : %s : \n",  ip_less_msg);
									
									printf("Buffer 2 : %s : \n",  buffer);
									
									add_receive_count(receivers_sock_fd);
									add_send_count(socket_index);
									
									printf("Socket fd to send in server : %d\n",receivers_sock_fd);
									if(receivers_sock_fd != -1){
										if (sendall(receivers_sock_fd, buffer, &buffer_len) == -1) 
											printf("Client side send error, msg : \n", buffer_len);
										else
											execute_relayed_command(senders_ip, receivers_ip, ip_less_msg);
									}
									else
										printf("Incorrect socket fd at server send \n");
								}
								//free(buffer);
							 }						
							//printf("port_on_login : %d  ", port_on_login);
								
							fflush(stdout);
                        }
						//Freeing buffer just to be safe, already freeing it in the loops above.
                        free(buffer);
                    }
                }
            }
        }
    }

    return 0;
}

void get_login_attributes(char* cmd, char *cmd_header, char *server_ip_address, char *server_port_number){	
  char command[200];
  printf(">>>>>>>>>>>>>>>cmd : %s : ", cmd);
  strcpy(command,cmd);
  char *split = strtok(command, " ");
  if(split != NULL)
  {
    strcpy(cmd_header,split);
    split = strtok(NULL, " ");
  }
  if(split != NULL)
  {
    strcpy(server_ip_address,split);
    split = strtok(NULL, " ");
  }
  if(split != NULL)
    strcpy(server_port_number,split);
    
    printf(">>>>>>>>>>>>>>>cmd header : %s : ", cmd_header);
     printf(">>>>>>>>>>>>>>>server_ip_address : %s : ", server_ip_address);
    
   //memset(split, 0, sizeof(split));
  
}

void get_block_cmd_attributes(char* cmd, char *cmd_header, char *server_ip_address){
	char command[200];
	strcpy(command,cmd);
  	char *split = strtok(command, " ");
  	if(split != NULL)
    {
	    strcpy(cmd_header,split);
	    split = strtok(NULL, " ");
    }
    if(split != NULL)
    	strcpy(server_ip_address,split);
}

void get_send_cmd_attributes(char* cmd, char *cmd_header, char *ip_and_msg){	
	char command[500];
	strcpy(command,cmd);
	char *split = strtok(command, " ");
	if(split != NULL)
	{
		strcpy(cmd_header,split);
		split = strtok(NULL, "");
	}
	strcpy(ip_and_msg,split);
}

char* generate_msg_from_client_list(){
	char *list_data_str = NULL;
	string_concat(&list_data_str,"list_data~");
	struct client_node *temp_node = root_node;
	
	while(temp_node != NULL){
		
		string_concat(&list_data_str, temp_node->host_name);
		string_concat(&list_data_str,"#");
		string_concat(&list_data_str, temp_node->ip_address);
		string_concat(&list_data_str,"#");
		char port_number_str[5];
		sprintf(port_number_str, "%d", temp_node->port_number);
		string_concat(&list_data_str, port_number_str);
		string_concat(&list_data_str,"&");
		temp_node = temp_node->next;
	}
	
	return list_data_str;
}


/**
* Splits the incoming list data message to linked list
* Ref - https://stackoverflow.com/questions/4693884/nested-strtok-function-problem-in-c
**/
void generate_client_list_from_msg(char *list_data){	

 	clear_list();
	char *header = NULL;
	header = strtok(list_data, "~");
	if(header!=NULL && strcmp(header, "login_info")==0){
		header = strtok(NULL, "~");
		list_data = strtok(NULL, "~");
	}
	else
		list_data = strtok(NULL, "~");
	
	char *remaining_node = NULL;
    char *node = NULL;
	node = strtok_r(list_data, "&", &remaining_node);

    while (node != NULL)
    {
        char *remaining_node_data = NULL;
        char *node_data = NULL;
		node_data = strtok_r(node, "#", &remaining_node_data);
		
		struct client_node *new_c_node = (struct client_node*) malloc(sizeof(struct client_node));
		
		if(node_data != NULL){
			strcpy(new_c_node->host_name, node_data);
            node_data = strtok_r(NULL, "#", &remaining_node_data);
		}
		if(node_data != NULL){
			strcpy(new_c_node->ip_address, node_data);
            node_data = strtok_r(NULL, "#", &remaining_node_data);
		}
		if(node_data != NULL)
			new_c_node->port_number = atoi(node_data);
		
		new_c_node->next =NULL;
		
		//Setting the linked list data from list data message
		
		if(root_node==NULL)
			root_node = new_c_node;
		else{
			struct client_node *temp = root_node;
			
			while(temp->next != NULL)
				temp=temp->next;

			temp->next = new_c_node;				
		}
        node = strtok_r(NULL, "&", &remaining_node);
    }
}

int sendall(int socket_fd, char *buf, int *len){
	int total = 0; // how many bytes we've sent
	int bytesleft = *len; // how many we have left to send
	int n;
	while(total < *len) {
		n = send(socket_fd, buf+total, bytesleft, 0);
		if (n == -1) { break; }
		total += n;
		bytesleft -= n;
	}
	*len = total; // return number actually sent here
	return n==-1?-1:0; // return -1 on failure, 0 on success
}

int login_to_server(char *server_ip, int server_port){
	//printf("connect_to_host, server_ip : %s\n", server_ip);
    int fdsocket, len;
    struct sockaddr_in remote_server_addr;

    fdsocket = socket(AF_INET, SOCK_STREAM, 0);
    if(fdsocket < 0)
       perror("Failed to create socket");

    bzero(&remote_server_addr, sizeof(remote_server_addr));
    remote_server_addr.sin_family = AF_INET;
    inet_pton(AF_INET, server_ip, &remote_server_addr.sin_addr);
    remote_server_addr.sin_port = htons(server_port);

    if(connect(fdsocket, (struct sockaddr*)&remote_server_addr, sizeof(remote_server_addr)) < 0){
    	perror("Connect failed");
    	return -1;
    }

    return fdsocket;
}

/**
* get_IP_address : creates a dummy UDP socket to check for the external ip address of the host
* returns char pointer to the IP Address char array
**/
char* get_IP_address(){	
	int dummy_udp_sock_fd;
    int sockaddr_len = sizeof(struct sockaddr);
    struct sockaddr_in google_addr, host_ext;

    if((dummy_udp_sock_fd=socket(AF_INET, SOCK_DGRAM, 0))<0)
    	perror("Failed to create udp socket for ip check\n");
  
	bzero(&google_addr, sizeof(google_addr));
    google_addr.sin_family = AF_INET;
    inet_pton(AF_INET, "8.8.8.8", &google_addr.sin_addr);
    google_addr.sin_port = htons(53);

   	if(connect(dummy_udp_sock_fd, (struct sockaddr*)&google_addr, sizeof(google_addr)) < 0)
        perror("Connect failed while connecting udp socket for ip check\n");
	
	getsockname(dummy_udp_sock_fd, (struct sockaddr *) &host_ext, &sockaddr_len);
	close(dummy_udp_sock_fd);
	return inet_ntoa(host_ext.sin_addr);
}

int get_port_on_login(char* login_msg){
	char msg[32];
	strcpy(msg, login_msg);
	printf("Getting the port number start : %s", msg);
	
	if(strncmp(msg, "login_info", 10)==0){
		//printf("Getting the port number start : %s", login_msg);
		char *port_number_str ;
		
		port_number_str = strtok(login_msg, "~");
		printf("split : %s", port_number_str);
		port_number_str = strtok(NULL, "");
		//strncpy(port_number_str, login_msg+11, 4);
		printf("Getting the port number on login : %s", port_number_str);
		//int port_number_int = -1;
		//sscanf(port_number_str, "%d", &port_number_int);
		//return 9002;
		return atoi(port_number_str);
	}
	return -1;
}

void get_ip_from_message(char *msg, char *IP, int remove_ip_frm_msg){
	strcpy(IP, msg);
	char *split = strtok(IP, " ");
}

int get_socketfd_by_ip(char *ip){
	struct client_node *temp_node = root_node;
	
	while(temp_node != NULL){
		if(strcmp(temp_node->ip_address, ip)==0)
			return temp_node->socket_fd;
		temp_node = temp_node->next;
	}
	return -1;
}

void get_ip_by_socketfd(int socket_fd, char* ip){
	struct client_node *temp_node = root_node;
	
	while(temp_node != NULL){
		if(temp_node->socket_fd == socket_fd){
			strcpy(ip, temp_node->ip_address);
			return;
		}
		temp_node = temp_node->next;
	}
}

void clear_list(){
	struct client_node *current;
	while(root_node != NULL){
		current = root_node;
		root_node = current->next;
		free(current);
		current = NULL;
	}
	
	if(root_node == NULL)
		printf("root_node is null");
	else
		printf("root_node is not null");
	
}

/**int has_list_header(char * msg){
	char msg[32];
	strcpy(msg, login_msg);
}**/

/**
* Concats two dynamic char arrays
* Ref : http://albertech.blogspot.com/2011/11/dynamically-concatenate-string-in-c-c99.html
**/
void string_concat(char **str, const char *str2) {
    char *tmp = NULL;

    // Reset *str
    if ( *str != NULL && str2 == NULL ) {
        free(*str);
        *str = NULL;
        return;
    }
    // Initial copy
    if (*str == NULL) {
        *str = (char*)calloc( strlen(str2)+1, sizeof(char) );
        memcpy( *str, str2, strlen(str2) );
    }
    else { // Append
        tmp = (char*)calloc( strlen(*str)+1, sizeof(char) );
        memcpy( tmp, *str, strlen(*str) );
        *str = (char*)calloc( strlen(*str)+strlen(str2)+1, sizeof(char) );
        memcpy( *str, tmp, strlen(tmp) );
        memcpy( *str + strlen(*str), str2, strlen(str2) );
        free(tmp);
    }
}

int is_valid_ip_address(char *ip_address){
	int result = -1;
    struct sockaddr_in sa;
    result = inet_pton(AF_INET, ip_address, &(sa.sin_addr));
    printf("isValidIpAddress : Is valid ip : %d \n", result);
    //result = does_ip_exists_in_list(ip_address);
    return result;
}

int does_ip_exists_in_list(char *ip_address){
	struct client_node *temp_node = root_node;
	//int result = -1;
	
	while(temp_node != NULL){
		if(strcmp(ip_address, temp_node->ip_address)==0){
			printf("yes does_ip_exists_in_list : %s\n", temp_node->ip_address);
			return 1;
		}		
		temp_node = temp_node->next;
	}
	return 1;
}

int is_valid_port_number(char *port_number){
	int result = -1;
	int port_number_len = strlen(port_number);

    for(int i=0; i<port_number_len-1; i++){
    	if(isdigit(port_number[i])==0){
    		printf("isValidPortNumber : got a non-digit at %d\n", i);
    		return -1;
    	}
    }
    return 1;
}


/**************** Linked List Implementation *******************/


/**
* Inserts client node such that sorted by port number
**/
void insert_client_node(int port_number, int socket_fd){
	struct sockaddr_in addr;
    int addr_size = sizeof(struct sockaddr_in);
    getpeername(socket_fd, (struct sockaddr *)&addr, &addr_size);
    
    char *IP = inet_ntoa(addr.sin_addr);
    
    if(!inet_aton(IP,&addr)){
      printf("Error in insert_client_node : IP issue");
    }
    
    struct hostent * host = gethostbyaddr(&addr,strlen(IP),AF_INET);

    struct client_node *new_c_node = (struct client_node*) malloc(sizeof(struct client_node));
    
    new_c_node->socket_fd = socket_fd;
	new_c_node->port_number = port_number;
	snprintf(new_c_node->ip_address, sizeof(new_c_node->ip_address), "%s", IP);
	snprintf(new_c_node->host_name, sizeof(new_c_node->host_name), "%s", host->h_name);
	new_c_node->logging_status = LOGGED_IN;
	
	struct client_node *current_node;
    if (root_node == NULL || (root_node)->port_number >= new_c_node->port_number)
    {
        new_c_node->next = root_node;
        root_node = new_c_node;
    }
    else 
    {
        current_node = root_node;
        
        while (current_node->next!=NULL &&
               current_node->next->port_number < new_c_node->port_number)
        {
        //	printf("current node %-5d%-35s%-20s%-8d-%d\n", current_node->socket_fd, current_node->host_name, current_node->ip_address, current_node->port_number);
	
            current_node = current_node->next;
        }
        new_c_node->next = current_node->next;
        //printf("current node in end %-5d%-35s%-20s%-8d-%d\n", current_node->socket_fd, current_node->host_name, current_node->ip_address, current_node->port_number);
	
       // printf("new node %-5d%-35s%-20s%-8d-%d\n", new_c_node->socket_fd, new_c_node->host_name, new_c_node->ip_address, new_c_node->port_number);
	
        current_node->next = new_c_node;
    }
}

void broadcast_to_logged_in_clients(int sender_sock_fd, char *buffer){
	struct client_node *temp_node = root_node;
	
	char ip[64];
	get_ip_by_socketfd(sender_sock_fd, ip);
	
	printf("IP from : %s, buffer : %s", ip, buffer);
	
	char* msg=NULL;
	string_concat(&msg, buffer);
	//printf("msg : %s", ip, msg);
	char *split = strtok(msg, "~");
//	printf("split : %s", split);
	
	msg = strtok(NULL, "");
	printf("msg 2 : %s", msg);
	
	char *ip_and_msg=NULL;
	
	string_concat(&ip_and_msg,ip);
	string_concat(&ip_and_msg," ");
	string_concat(&ip_and_msg,msg);
	
	printf("ip_and_msg : %s", ip_and_msg);
	
	int msg_len =strlen(ip_and_msg);
	
	char broadcast_ip[32] = "255.255.255.255";
	
	add_send_count(sender_sock_fd);
	
	while(temp_node != NULL){
		
		if(temp_node->logging_status == LOGGED_IN && temp_node->socket_fd != sender_sock_fd){
			printf("logged in ,sending message : %s", temp_node->ip_address);
			//Broadcast to this client : todo-blocked!!
			int current_sock_fd = temp_node->socket_fd;
			add_receive_count(current_sock_fd);
			if (sendall(current_sock_fd, ip_and_msg, &msg_len) == -1) 
				printf("Broadcast error, msg : \n", msg_len);
			else
				execute_relayed_command(ip, broadcast_ip, msg);
		}
		temp_node = temp_node->next;
	}
}

/**
* Removing client node in sorted list
* Ref : http://www.geeksforgeeks.org/linked-list-set-3-deleting-node/
**/
void remove_client_node(int socket_index){
    
    // Store head node
    struct client_node *current = root_node;
	struct client_node *prev;
 
    // If head node itself holds the key to be deleted
    if (current != NULL && current->socket_fd == socket_index)
    {
        root_node = current->next;   // Changed head
        free(current);               // free old head
        return;
    }
    // Search for the key to be deleted, keep track of the
    // previous node as we need to change 'prev->next'
    while (current != NULL && current->socket_fd != socket_index)
    {
        prev = current;
        current = current->next;
    }
 
    // If key was not present in linked list
    if (current == NULL) return;
 
    // Unlink the node from linked list
    prev->next = current->next;
    free(current);  // Free memory
}

void log_client_node(int socket_index, int status){
	struct client_node *temp_node = root_node;
	
	while(temp_node != NULL){
		if(temp_node->socket_fd == socket_index){
			temp_node->logging_status = status;
			printf("changing logging status of server %s : to : %d", temp_node->host_name, temp_node->logging_status);
		}
		temp_node = temp_node->next;
	}
}

void print_client_nodes(){
	struct client_node *temp_node = root_node;
	int i =1;
	
	while(temp_node != NULL){
		printf("%-5d%-35s%-20s%-8d   %d   %d\n", i, temp_node->host_name, temp_node->ip_address, temp_node->port_number, 
						temp_node->socket_fd, temp_node->logging_status);
		temp_node = temp_node->next;
		i++;
	}
}

void add_receive_count(int receivers_sock_fd){
	struct client_node *temp_node = root_node;
	
	while(temp_node != NULL){
		if(temp_node->socket_fd==receivers_sock_fd){
			temp_node->msg_received += 1;
			return;
		}
		temp_node = temp_node->next;
	}
}

void add_send_count(int socket_index){
	struct client_node *temp_node = root_node;
	
	while(temp_node != NULL){
		if(temp_node->socket_fd==socket_index){
			temp_node->msg_sent += 1;
			return;
		}
		temp_node = temp_node->next;
	}
}

void execute_author_command(char* command_str, int type){
	cse4589_print_and_log("[%s:SUCCESS]\n", strtok(command_str, "\n"));
	cse4589_print_and_log("I, %s, have read and understood the course academic integrity policy.\n", "sa32");
	cse4589_print_and_log("[%s:END]\n", strtok(command_str, "\n"));
}

void execute_login_command(char* command_str, int status){
	
	if(status == SUCCESS)
		cse4589_print_and_log("[%s:SUCCESS]\n", "LOGIN");
	else if(status == FAIL)
		cse4589_print_and_log("[%s:ERROR]\n", "LOGIN");
		
	cse4589_print_and_log("[%s:END]\n", command_str);
}

void execute_IP_command(char* command_str, int type){
	char * IP_address= get_IP_address();
	cse4589_print_and_log("[%s:SUCCESS]\n", strtok(command_str, "\n"));
	cse4589_print_and_log("IP:%s\n", IP_address);
	cse4589_print_and_log("[%s:END]\n", strtok(command_str, "\n"));
}

void execute_port_command(char *command_str, int type, int port_number){
	cse4589_print_and_log("[%s:SUCCESS]\n", strtok(command_str, "\n"));
	cse4589_print_and_log("PORT:%d\n", port_number);
	cse4589_print_and_log("[%s:END]\n", strtok(command_str, "\n"));
}

void execute_list_command(char* command_str, int type){
	cse4589_print_and_log("[%s:SUCCESS]\n", strtok(command_str, "\n"));
	
	struct client_node *temp_node = root_node;
	int i =1;
	
	while(temp_node != NULL){
		cse4589_print_and_log("%-5d%-35s%-20s%-8d\n", i, temp_node->host_name, temp_node->ip_address, temp_node->port_number);
		temp_node = temp_node->next;
		i++;
	}
	cse4589_print_and_log("[%s:END]\n", strtok(command_str, "\n"));
}

void execute_refresh_command(char* command_str){
	cse4589_print_and_log("[%s:SUCCESS]\n", "REFRESH");
	cse4589_print_and_log("[%s:END]\n", "REFRESH");
}

void execute_send_command(char* command_str, int status){
	
	if(status == SUCCESS)
		cse4589_print_and_log("[%s:SUCCESS]\n", "SEND");
	else if(status == FAIL)
		cse4589_print_and_log("[%s:ERROR]\n", "SEND");
		
	cse4589_print_and_log("[%s:END]\n", "SEND");
}

void execute_statistics_command(char *cmd){
	cse4589_print_and_log("[%s:SUCCESS]\n", "STATISTICS");
	
	struct client_node *temp_node = root_node;
	int i =1;
	
	while(temp_node != NULL){
		char *status;
		if(temp_node->logging_status == LOGGED_IN)
			status = "logged-in";
		else if(temp_node->logging_status == LOGGED_OUT)
			status = "logged-out";
			
		cse4589_print_and_log("%-5d%-35s%-8d%-8d%-8s\n", i, temp_node->host_name, 
						temp_node->msg_sent, temp_node->msg_received, status);
		temp_node = temp_node->next;
		i++;
	}
	cse4589_print_and_log("[%s:END]\n", "STATISTICS");

}

void execute_broadcast_command(char* command_str){
	cse4589_print_and_log("[%s:SUCCESS]\n", "BROADCAST");
	cse4589_print_and_log("[%s:END]\n", "BROADCAST");
}

void execute_block_command(char* command_str, int status){
	if(status == SUCCESS)
		cse4589_print_and_log("[%s:SUCCESS]\n", "BLOCK");
	else if(status == FAIL)
		cse4589_print_and_log("[%s:ERROR]\n", "BLOCK");
		
	cse4589_print_and_log("[%s:END]\n", "BLOCK");
}

void execute_unblock_command(char* command_str, int status){
	if(status == SUCCESS)
		cse4589_print_and_log("[%s:SUCCESS]\n", "UNBLOCK");
	else if(status == FAIL)
		cse4589_print_and_log("[%s:ERROR]\n", "UNBLOCK");
		
	cse4589_print_and_log("[%s:END]\n", "UNBLOCK");
}

void execute_blocked_command(char* command_str, int status){
	if(status == SUCCESS)
		cse4589_print_and_log("[%s:SUCCESS]\n", "BLOCKED");
	else if(status == FAIL)
		cse4589_print_and_log("[%s:ERROR]\n", "BLOCKED");
		
	cse4589_print_and_log("[%s:END]\n", "BLOCKED");
}

void execute_receive_command(char* client_ip, char * msg){
	cse4589_print_and_log("[%s:SUCCESS]\n", "RECEIVED");
	cse4589_print_and_log("msg from:%s\n[msg]:%s\n", client_ip, msg);
	cse4589_print_and_log("[%s:END]\n", "RECEIVED");
}

void execute_relayed_command(char* from_client_ip, char * to_client_ip, char * msg){
	cse4589_print_and_log("[%s:SUCCESS]\n", "RELAYED");
	cse4589_print_and_log("msg from:%s, to:%s\n[msg]:%s\n", from_client_ip, to_client_ip, msg);
	cse4589_print_and_log("[%s:END]\n", "RELAYED");
}

void execute_exit_command(char* command_str){
	cse4589_print_and_log("[%s:SUCCESS]\n", command_str);
	cse4589_print_and_log("[%s:END]\n", command_str);
}

void execute_logout_command(char* command_str){
	cse4589_print_and_log("[%s:SUCCESS]\n", "LOGOUT");
	cse4589_print_and_log("[%s:END]\n", "LOGOUT");
}






