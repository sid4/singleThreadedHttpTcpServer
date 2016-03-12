//strcasestr fix
#define _GNU_SOURCE
#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<sys/types.h>
#include<sys/socket.h>
#include<netinet/in.h>
#include<unistd.h>
#include<time.h>
#include<fcntl.h>
#include<sys/stat.h>
//minimum arguments required for running server
#define MIN_ARGS 2
#define MAX_BACKLOG 5
//buffer size for reading client requests
#define READ_BUFFER_SIZE 400
//response header size
#define RESPONSE_HEADER_SIZE 256
//buffer size for reading from files and writing to socket
#define CHUNKED_READ_WRITE_BUFFER_SIZE 1000
//Timeout for persistent connections
#define PERSISTENT_CONNECTION_TIMEOUT 5
#define TRUE 1
#define FALSE 0
void signal_error(char *err_msg);
void handle_insufficient_args(int argc);
char *getRequestedResource(char *request);
void getErrorHeader(int error_code, char* header);
int isValidRequest(char *request);

char *generateFileFoundHeader(unsigned long size, int is_html);
void writeFileToSocket(int socket_fd_new, int file_fd);
void generateFileFoundHeaderAndWriteToSocket(int file_size, char* resource_name,
		int socket_fd);
void generateAndWriteErrorHeader(int socket_fd_new, int errno);
int isPersistentConnection(char *request);
void closeSocket(int socket_fd_new, int persistent_connection);
int processRequest(int socket_fd_new, int called_from_close_socket_fn);

int main(int argc, char *argv[]) {
	//setvbuf(stdout,NULL,_IOLBF,0);
	if (!argc < MIN_ARGS) {
		int listen_status, bind_status, socket_file_descr,
				socket_file_descr_new, port;
		socklen_t client_addr_size;
		struct sockaddr_in server, client;
		port = atoi(argv[1]);
		//create socket
		socket_file_descr = socket(AF_INET, SOCK_STREAM, 0); //AF_INET is the domain, SOCK_STREAM is the communication style
		if (socket_file_descr == -1) {
			signal_error("Failed creating a socket for the server");
		}
		//clear the struct
		memset(&server, 0, sizeof(server));
		//populate the server address details
		server.sin_family = AF_INET;
		//assigning the network byte order equivalent of port no
		server.sin_port = htons(port);
		server.sin_addr.s_addr = INADDR_ANY;
		//bind socket
		bind_status = bind(socket_file_descr, (struct sockaddr *) &server,
				sizeof(server));
		if (bind_status == -1) {
			signal_error("Socket binding failed");
		}
		while (1) {
			//listen to port
			listen_status = listen(socket_file_descr, MAX_BACKLOG);
			if (listen_status == -1) {
				signal_error("Failed to listen to the server port");
			}
			client_addr_size = sizeof(client);
			socket_file_descr_new = accept(socket_file_descr,
					(struct sockaddr *) &client, &client_addr_size);
			if (socket_file_descr_new < 0) {
				signal_error("Error in call to accept");
			}
			//char *request=
			processRequest(socket_file_descr_new, FALSE);
			//closeSocket(socket_file_descr_new, request);
		}
	} else {
		signal_error(
				"insufficient arguments. Port # is required for server boot up.");
	}
	return 0;
}
/**
 * Closes a socket, if it is a non-persistent request.
 * In case of persistent request, it waits for some time for receiving request.
 * If in that window of time no request arrives, the socket is closed.
 * If a request is received in that window of time, then the request is processed
 * and on the basis of the connection type(persistent/non-persistent) of request, a decision is made to
 * whether wait to serve even more requests or close socket
 */
void closeSocket(int socket_fd_new, int persistent_connection) {
	if (persistent_connection) {
		//setting up the max waiting time for a request to arrive
		fd_set set;
		struct timeval max_wait;
		FD_ZERO(&set);
		FD_SET(socket_fd_new, &set);
		max_wait.tv_sec = PERSISTENT_CONNECTION_TIMEOUT;
		max_wait.tv_usec = 0;
		int persistent = 1;
		while (persistent && (select(socket_fd_new + 1, &set, NULL, NULL, &max_wait) == 1)) {
			//printf("\nprocessing persistent request");
			persistent = processRequest(socket_fd_new, TRUE);
			//setting up the max waiting time for a request to arrive
			FD_ZERO(&set);
			FD_SET(socket_fd_new, &set);
			max_wait.tv_sec = PERSISTENT_CONNECTION_TIMEOUT;
			max_wait.tv_usec = 0;
		}
	}
	//close socket when all the persistent connections are handled or when a timeout occurs or if it is not a persistent connection
	//printf("\nclosing socket\n");
	close(socket_fd_new);
}
/**
 * get HTTP request from the socket and evaluate/parse
 */
void getHTTPRequest(int socket_fd_new, int *valid, int *persistent_connection,
		char **resource, char *request, int *readc) {
	//char *request = (char *) calloc(1, READ_BUFFER_SIZE);
	//read from client-blocking call
	*readc=read(socket_fd_new, request, READ_BUFFER_SIZE - 1);
	//checking if request is valid
	*valid = isValidRequest(request);
	//checking if request is for persistent connection
	*persistent_connection = isPersistentConnection(request);
	//parsing the request for requested resource from http request header
	*resource = getRequestedResource(request);
}

/**
 * Processes Requests.
 * Reads the request from the socket. Checks if the request is a valid request.
 * In case of invalid request, returns a response with bad request error code.
 * In case it is a valid request, checks for the resource in file system.
 * If the resource is found, then it sends the appropriate headers and the requested resource.
 * If the resource is not found, then sends the Resource Not Found, 404 Error header
 * Returns: is connection persistent?
 */
int processRequest(int socket_fd_new, int called_from_close_socket_fn) {
	int validRequest;
	int persistent_connection;
	char *resource;
	char request[READ_BUFFER_SIZE] = "";
	int readc;
	getHTTPRequest(socket_fd_new, &validRequest, &persistent_connection,
			&resource, request,&readc);
	if (!validRequest) {
		//handle invalid request
		//if(readc==0), client has shutdown
		if(!readc==0){
		generateAndWriteErrorHeader(socket_fd_new, 500);
		}
		memset(request, 0, READ_BUFFER_SIZE);
		return persistent_connection;
	}
	//Get the file descriptor of the requested resource
	int req_file_fd = open(resource + 1, O_RDONLY);
	free(resource);
	if (req_file_fd == -1) {
		//case:file not found
		//Generate and write 404 error in response
		generateAndWriteErrorHeader(socket_fd_new, 404);
	} else {
		//case:file found
		//getting the file size
		struct stat file_stat;
		fstat(req_file_fd, &file_stat);
		unsigned long size = (unsigned long) file_stat.st_size;
		//Generate file found header and write it in response.
		generateFileFoundHeaderAndWriteToSocket(size, resource + 1,
				socket_fd_new);
		//Write file to response
		writeFileToSocket(socket_fd_new, req_file_fd);
	}
	if (!called_from_close_socket_fn) {
		//free(resource);
		closeSocket(socket_fd_new, persistent_connection);
	}
	return persistent_connection;
}

/**
 * Checks if its a persistent connection by reading the HTTP request header
 */
int isPersistentConnection(char *request) {
	return NULL==strcasestr(request, "Connection: close");
}

/**
 * Check if the http request is valid.
 */
int isValidRequest(char *request) {
	int i;
	int valid = 1;
	if (strlen(request) < 12) {
		valid = 0;
		return valid;

	}
	//checking if the first three char are GET
	if (!(request[0] == 'G' && request[1] == 'E' && request[2] == 'T'
			&& request[3] == ' ')) {
		valid = 0;
		return valid;
	}
	for (i = 4;
			!(request[i] == '\r' || request[i] == '\n' || request[i] == ' ');
			i++)
		;
	if (request[i] == '\r' || request[i] == '\n') {
		valid = 0;
		return valid;
	}
	//checking if the request header's first line has the HTTP protocol mentioned
	if (!(request[i + 1] == 'H' && request[i + 2] == 'T'
			&& request[i + 3] == 'T' && request[i + 4] == 'P')) {
		valid = 0;
		return valid;
	}
	return valid;
}

/**
 * Generate the Error header(with the given error no.) and write it to socket
 */
void generateAndWriteErrorHeader(int socket_fd, int errno) {
	char output[RESPONSE_HEADER_SIZE];
	getErrorHeader(errno, output);
	write(socket_fd, output, sizeof(output));
}
/**
 * Generate the File found header and write it to socket
 */
void generateFileFoundHeaderAndWriteToSocket(int file_size, char* resource_name,
		int socket_fd) {
	char *header = generateFileFoundHeader(file_size,
			(strstr(resource_name, ".html") != NULL) ? TRUE : FALSE);
	write(socket_fd, header, strlen(header));
}

/*
 * Reads the requested file and writes it to client.
 * The output is read from the file and as well as written to socket in chunks.
 * This mechanism handles the situation wherein the file to be written is very big
 * and it might not be practical to allocate that size in one go on the heap.
 */
void writeFileToSocket(int socket_fd, int file_fd) {
	unsigned char file_buffer[CHUNKED_READ_WRITE_BUFFER_SIZE];
	//bytes read from file into buffer
	int readc;
	//bytes written to socket
	int writec;
	//Read, write in chunks
	for (readc = read(file_fd, file_buffer, (sizeof file_buffer) - 1);
			readc > 0;
			readc = read(file_fd, file_buffer, (sizeof file_buffer) - 1)) {
		unsigned char *temp = file_buffer;
		for (writec = write(socket_fd, temp, readc); readc > 0 && writec > 0;
				readc -= writec, temp += writec, writec = write(socket_fd, temp,
						readc))
			;
	}
	if (readc < 0 || writec < 0) {
		signal_error(
				"Error occured during copying file from file sytem to socket");
	}
	close(file_fd);
}

/*
 * Generates the header for a file being sent as a reponse.
 **/
char *generateFileFoundHeader(unsigned long size, int is_html) {
	char header[RESPONSE_HEADER_SIZE] = "";
	//getting current time
	time_t current_time = time(NULL);
	//ctime has a /n appended to the returned string, hence only a single n at the end of header
	//generating header
	snprintf(header, sizeof header,
			"HTTP/1.1 %d %s\r\nServer:X\r\nContent-Length:%lu\r\nContent-Type:%s\r\nDate:%s\n",
			200,

			"OK", size, (is_html) ? "text/html" : "application",
			ctime(&current_time));
	//trimming the header
	char *header_trimmed = (char *) calloc(1, strlen(header) + 1);
	{
		int i = 0;
		for (; i < strlen(header) + 1; i++) {
			header_trimmed[i] = header[i];
		}
	}
	return header_trimmed;
}

/**
 *Generates the error header for the given error code
 **/
void getErrorHeader(int error, char *header) {
	//getting the current time
	time_t current_time = time(NULL);
	//ctime has a /n appended to the returned string, hence only a single n at the end of header
	snprintf(header, RESPONSE_HEADER_SIZE,
			"HTTP/1.1 %d %s\r\n Server: X\r\nContent-Length: 0\r\nDate: %s\n",
			error, (error == 404 ? "Not Found" : "Bad Request"),
			ctime(&current_time));
}

/**
 * Parses the resource/file name requested in the HTTP request header
 */
char* getRequestedResource(char *request) {
	char *start = strchr(request, ' ');
	start += 1;
	char *end = strchr(start, ' ');
	end -= 1;
	char *resource = (char *) calloc(1, end - start + 1);
	memcpy(resource, start, end - start + 1);
	resource[end - start + 1] = '\0';
	return resource;
}

/*
 * Prints the error to the standard error stream and exits the program
 */
void signal_error(char *err_msg) {
	fprintf(stderr, err_msg);
	fprintf(stderr, "shutting down");
	exit(1);
}
