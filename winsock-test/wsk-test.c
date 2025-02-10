// code from https://www.binarytides.com/winsock-socket-programming-tutorial/

/*
	Initialise Winsock
*/

#include<stdio.h>
#include<winsock2.h>

#pragma comment(lib,"ws2_32.lib") //Winsock Library


int main(int argc , char *argv[])
{
	WSADATA wsa;

    char *hostname = "khaldun.net";
	char ip[100];
	struct hostent *he;
	struct in_addr **addr_list;
	int i;

    SOCKET s;
    struct sockaddr_in server;
    char *message , server_reply[101];
    int recv_size;
	
	printf("\nInitialising Winsock...");
	if (WSAStartup(MAKEWORD(2,2),&wsa) != 0)
	{
		printf("Failed. Error Code : %d",WSAGetLastError());
		return 1;
	}
	
	printf("Initialised.\n");


    if ( (s = socket( AF_INET , SOCK_STREAM , 0 )) == INVALID_SOCKET)
	{
		printf("Could not create socket : %d" , WSAGetLastError());
	}
	puts("Socket created.");


    if ( (he = gethostbyname( hostname ) ) == NULL)
    {
        //gethostbyname failed
        printf("gethostbyname failed : %d" , WSAGetLastError());
        return 1;
    }
        
    //Cast the h_addr_list to in_addr , since h_addr_list also has the ip address in long format only
    addr_list = (struct in_addr **) he->h_addr_list;
    
    for(i = 0; addr_list[i] != NULL; i++) 
    {
        //Return the first one;
        strcpy(ip , inet_ntoa(*addr_list[i]) );
        printf("%s resolved to : %s\n" , hostname , ip);
    }

    server.sin_addr.s_addr = addr_list[0]->S_un.S_addr;  //inet_addr("142.250.72.110");
	server.sin_family = AF_INET;
	server.sin_port = htons( /*28900*/80 );

	//Connect to remote server
    printf("Attempting connection...");
	if (connect(s , (struct sockaddr *)&server , sizeof(server)) < 0)
	{
		puts("connect error");
        closesocket(s);
        WSACleanup();
		return 1;
	}
	
	puts("Connected");


    printf("Setting socket timeout...");
    int recvTimeout = 5000;
    int optLen = sizeof(int);
    if (setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (char *) &recvTimeout, optLen) == SOCKET_ERROR) {
        printf("setsockopt for SO_RCVTIMEO failed with error: %u\n", WSAGetLastError());
    }
    puts("socket timeout set!");

    /*//Send some data
	message = "GET / HTTP/1.1\r\n\r\n";
	if( send(s , message , strlen(message) , 0) < 0)
	{
		puts("Send failed");
        closesocket(s);
        WSACleanup();
		return 1;
	}
	puts("Data Send\n");*/

    //Receive a reply from the server
    printf("Listening for data for %ims...", recvTimeout);
	if((recv_size = recv(s , server_reply , 100 , 0)) == SOCKET_ERROR)
	{
		puts("recv failed");
	} else {
        printf("Reply received. recv_size: %i\n", recv_size);
        printf("Extracted string: %s compared with %s", server_reply, "\\basic\\\\secure\\");
        if (strncmp(server_reply, "\\basic\\\\secure\\", 15) == 0) {
            puts("Server is online!\n");
        } else puts("Server is offline :(\n");
    }

	puts(server_reply);

    closesocket(s);
    WSACleanup();

	return 0;
}