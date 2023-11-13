#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <ctype.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdbool.h>
#define BUFFERLENGTH 256

/* displays error messages from system calls */
void error(char *msg)
{
    perror(msg);
    exit(0);
}

bool isValidIPAddress(const char *ipAddress) {
    int ipArray[4];
    int result = sscanf(ipAddress, "%d.%d.%d.%d", &ipArray[0], &ipArray[1], &ipArray[2], &ipArray[3]);
    if (result == 4) {
        for (int i = 0; i < 4; i++) {
            if (ipArray[i] < 0 || ipArray[i] > 255) {
                return false;
            }
        }
        return true;
    }
    return false;
}

bool isValidPort(int port) {
    return port >= 0 && port <= 65535;
}

// Function to check if the IP address contains a hyphen
bool containsHyphen(const char *ipAddress) {
    return strchr(ipAddress, '-') != NULL;
}

// Function to check if the given port is a range
bool containsHyphenInPort(const char *port) {
    // Check if the port value itself contains a hyphen
    return strchr(port, '-') != NULL;
}

int main(int argc, char *argv[])
{
    int sockfd, n;
    struct addrinfo hints;
    struct addrinfo *result, *rp;
    int res;


    char buffer[BUFFERLENGTH];
    if (argc < 3) {
        fprintf (stderr, "usage %s hostname port\n", argv[0]);
        exit(1);
    }


    /* Obtain address(es) matching host/port */
    /* code taken from the manual page for getaddrinfo */

    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family = AF_UNSPEC;    /* Allow IPv4 or IPv6 */
    hints.ai_socktype = SOCK_STREAM; /* Datagram socket */
    hints.ai_flags = 0;
    hints.ai_protocol = 0;          /* Any protocol */

    res = getaddrinfo(argv[1], argv[2], &hints, &result);
    if (res != 0) {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(res));
        exit(EXIT_FAILURE);
    }

    /* getaddrinfo() returns a list of address structures.
       Try each address until we successfully connect(2).
       If socket(2) (or connect(2)) fails, we (close the socket
       and) try the next address. */

    for (rp = result; rp != NULL; rp = rp->ai_next) {
        sockfd = socket(rp->ai_family, rp->ai_socktype,
                        rp->ai_protocol);
        if (sockfd == -1)
            continue;

        if (connect(sockfd, rp->ai_addr, rp->ai_addrlen) != -1)
            break;                  /* Success */

        close(sockfd);
    }

    if (rp == NULL) {               /* No address succeeded */
        fprintf(stderr, "Could not connect\n");
        exit(EXIT_FAILURE);
    }

    freeaddrinfo(result);           /* No longer needed */

    /* Prepare message based on the specified operation */

    if (argc == 4){
        if (argv[3][0] == 'L'){
            snprintf(buffer, BUFFERLENGTH, "LIST_RULES\n");
        } // command="A 147.188.192.41 443"
        else if (argv[3][0] == 'A'){ // Check if argv[3] starts with an 'A'
            // Remove an 'A' and get the rest of the string
            char *ruleText = argv[3] + 2;
            snprintf(buffer, BUFFERLENGTH, "ADD_RULE %s\n", ruleText);
        } else if (argv[3][0] == 'D'){
            char *ruleText = argv[3] + 2;
            snprintf(buffer, BUFFERLENGTH, "DELETE_RULE %s\n", ruleText);
        }
        else if (argv[3][0] == 'C'){ // Check Rules
            // ./client localhost 1234 "C 192.168.1.1 8080"
            char *ruleText = argv[3] + 2;
            char *ipAddress = strtok(ruleText, " ");
            char *portString = strtok(NULL, " ");
            if (ipAddress != NULL && portString != NULL) {
                int port = atoi(argv[5]);
                // Convert the port string to an integer
                if ((containsHyphen(ipAddress)) || (containsHyphenInPort(portString)))
                {
                    printf("Illegal IP address or port specified\n");
                    close(sockfd);
                    exit(EXIT_FAILURE);
                }
                else if (!containsHyphen(ipAddress) && !containsHyphenInPort(portString)){
                    if (isValidIPAddress(ipAddress) && isValidPort(port)){
                        snprintf(buffer, BUFFERLENGTH, "CHECK_RULE %s %d\n", ipAddress, port);
                    }
                    else {
                        printf("Illegal IP address or port specified\n");
                        close(sockfd);
                        exit(EXIT_FAILURE);
                    }
                }
            } else{
                printf("Illegal IP address or port specified\n");
                close(sockfd);
                exit(EXIT_FAILURE);
            }
        }
        else {
            fprintf(stderr, "Illegal request\n");
            close(sockfd);
            exit(EXIT_FAILURE);
        }
    }
    else if (argc == 6) {
        if (argv[3][0] == 'A'){ // <ClientProgram> <serverHost> <serverPort> A <rule>
            snprintf(buffer, BUFFERLENGTH, "ADD_RULE %s %s\n", argv[4], argv[5]);
        }
        else if (argv[3][0] == 'D'){
            snprintf(buffer, BUFFERLENGTH, "DELETE_RULE %s %s\n", argv[4], argv[5]);
        }
        else if (argv[3][0] == 'C') { // <ClientProgram> <serverHost> <serverPort> C <IPAddress> <port> for checking an IP address and port
            // Convert the port argument to an integer
            int port = atoi(argv[5]);
            if ((containsHyphen(argv[4])) || (containsHyphenInPort(argv[5])))
            {
                printf("Illegal IP address or port specified\n");
                close(sockfd);
                exit(EXIT_FAILURE);
            }
            else if (!containsHyphen(argv[4]) && !containsHyphenInPort(argv[5])){
                if (isValidIPAddress(argv[4]) && isValidPort(port)){
                    snprintf(buffer, BUFFERLENGTH, "CHECK_RULE %s %d\n", argv[4], port);
                }
                else {
                    printf("Illegal IP address or port specified\n");
                    close(sockfd);
                    exit(EXIT_FAILURE);
                }
            }
        }
        else {
            fprintf(stderr, "Illegal request\n");
            close(sockfd);
            exit(EXIT_FAILURE);
        }
    }
    else {
        fprintf(stderr, "Illegal request\n");
        close(sockfd);
        exit(EXIT_FAILURE);
    }

    /* send message */
    n = write (sockfd, buffer, strlen(buffer));
    if (n < 0)
        error ("ERROR writing to socket");
    bzero (buffer, BUFFERLENGTH);

    /* wait for reply */
    n = read (sockfd, buffer, BUFFERLENGTH -1);
    if (n < 0)
        error ("ERROR reading from socket");
    printf ("%s\n",buffer);
    close(sockfd);
    return 0;
}
