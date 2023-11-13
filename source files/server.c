/* A threaded server in the internet domain using TCP
   The port number is passed as an argument */
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <ctype.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <stdbool.h>

#define BUFFERLENGTH 256
#define THREAD_IN_USE 0
#define THREAD_FINISHED 1
#define THREAD_AVAILABLE 2
#define THREADS_ALLOCATED 10


// Structure to represent a pair of IP address and port
struct queriedPair_t {
    int ipaddr[4];
    int port;
    struct queriedPair_t *next;
};

// firewallRule_t represents an individual rule with its IP address and port information.
struct firewallRule_t { //
    int ipaddr1[4];
    int ipaddr2[4];
    int port1;
    int port2;
    struct queriedPair_t *queriedPairs; // List of queried pairs for this rule
    int queriedBefore;  // Flag to track whether a query has been queried before for this rule
};

struct checkedQuery_t {
    int ipaddr[4];
    int port;
    struct checkedQuery_t *next;
};

// Global list of checked queries
struct checkedQuery_t *checkedQueries = NULL;

// firewallRules_t is a linked list structure that stores firewall rules.
struct firewallRules_t {
    struct firewallRule_t *rule; // Each node represents a rule (firewallRule_t). "147.188.192.41" "133"
    struct firewallRules_t *next; // pointer to the next rule
};

/* displays error messages from system calls */
void error(char *msg)
{
    perror(msg);
    exit(1);
};

struct threadArgs_t {
    int newsockfd;
    int threadIndex;
};


/* this is only necessary for proper termination of threads - you should not need to access this part in your code */
struct threadInfo_t {
    pthread_t pthreadInfo;
    pthread_attr_t attributes;
    int status;
};


int isExecuted = 0;
int returnValue = 0; /* not used; need something to keep compiler happy */
pthread_mutex_t mut = PTHREAD_MUTEX_INITIALIZER; /* the lock used for processing */
struct threadInfo_t *serverThreads = NULL;
struct firewallRules_t *rules = NULL;
int noOfThreads = 0;
pthread_rwlock_t threadLock =  PTHREAD_RWLOCK_INITIALIZER;
pthread_cond_t threadCond = PTHREAD_COND_INITIALIZER;
pthread_mutex_t threadEndLock = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t rulesMutex = PTHREAD_MUTEX_INITIALIZER; // Add a mutex to protect the global rules list

/* finds unused thread info slot; allocates more slots if necessary
   only called by main thread */
int findThreadIndex () {
    int i, tmp;

    for (i = 0; i < noOfThreads; i++) {
        if (serverThreads[i].status == THREAD_AVAILABLE) {
            serverThreads[i].status = THREAD_IN_USE;
            return i;
        }
    }

    /* no available thread found; need to allocate more threads */
    pthread_rwlock_wrlock (&threadLock);
    serverThreads = realloc(serverThreads, ((noOfThreads + THREADS_ALLOCATED) * sizeof(struct threadInfo_t)));
    noOfThreads = noOfThreads + THREADS_ALLOCATED;
    pthread_rwlock_unlock (&threadLock);
    if (serverThreads == NULL) {
        fprintf (stderr, "Memory allocation failed\n");
        exit (1);
    }
    /* initialise thread status */
    for (tmp = i+1; tmp < noOfThreads; tmp++) {
        serverThreads[tmp].status = THREAD_AVAILABLE;
    }
    serverThreads[i].status = THREAD_IN_USE;
    return i;
}

/* waits for threads to finish and releases resources used by the thread management functions. You don't need to modify this function */
void *waitForThreads(void *args) {
    int i, res;
    while (1) {
        pthread_mutex_lock(&threadEndLock);
        pthread_cond_wait(&threadCond, &threadEndLock);
        pthread_mutex_unlock(&threadEndLock);

        pthread_rwlock_rdlock(&threadLock);
        for (i = 0; i < noOfThreads; i++) {
            if (serverThreads[i].status == THREAD_FINISHED) {
                res = pthread_join (serverThreads[i].pthreadInfo, NULL);
                if (res != 0) {
                    fprintf (stderr, "thread joining failed, exiting\n");
                    exit (1);
                }
                serverThreads[i].status = THREAD_AVAILABLE;
            }
        }
        pthread_rwlock_unlock(&threadLock);
    }
}

int compareIPAddresses (const int *ipaddr1, const int *ipaddr2) {
    int i;
    for (i = 0; i < 4; i++) {
        if (ipaddr1[i] > ipaddr2[i]) {
            return 1;
        }
        else if (ipaddr1[i] < ipaddr2[i]) {
            return -1;
        }
    }
    return 0;
}

bool checkIPAddress (int *ipaddr1, int *ipaddr2, int *ipaddr) {
    int res;

    res =  compareIPAddresses (ipaddr, ipaddr1);
    if (compareIPAddresses (ipaddr, ipaddr1) == 0) {
        return true;
    }
    else if (ipaddr2[0] == -1) {
        return false;
    }
    else if (res  == -1) {
        return false;
    }
    else if (compareIPAddresses (ipaddr, ipaddr2) <= 0) {
        return true;
    }
    else {
        return false;
    }
}

// Helper function to convert IP array to string
char *convertIPArrayToString(int *ipArray, char *ipString, size_t ipStringSize) {
    snprintf(ipString, ipStringSize, "%d.%d.%d.%d", ipArray[0], ipArray[1], ipArray[2], ipArray[3]);
    return ipString;
}

int checkPort (int port1, int port2, int port) {
    if (port == port1) {
        return 0;
    }
    else if (port < port1) {
        return -1;
    }
    else if (port2 == -1 || port > port2) {
        return 1;
    }
    else {
        return 0;
    }
}


/* parses one IP address. Returns NULL if text does not start with a valid IP address, and a pointer  to the first character after the valid IP address otherwise */
char *parseIPaddress (int *ipaddr, char *text) {
    char *oldPos, *newPos;
    long int addr;
    int i;
    oldPos = text;
    for (i = 0; i <4; i++) {
        if (oldPos == NULL || *oldPos < '0' || *oldPos > '9') {
            return NULL;
        }
        addr = strtol(oldPos, &newPos, 10);
        if (newPos == oldPos) {
            return NULL;
        }
        if ((addr < 0)  || addr > 255) {
            ipaddr[0] = -1;
            return NULL;
        }
        if (i < 3) {
            if ((newPos == NULL) || (*newPos != '.')) {
                ipaddr[0] = -1;
                return NULL;
            }
            else newPos++;
        }
        else if ((newPos == NULL) || ((*newPos != ' ') && (*newPos != '-'))) {
            ipaddr[0] = -1;
            return NULL;
        }
        ipaddr[i] = addr;
        oldPos = newPos;
    }
    return newPos;
}

char *parsePort (int *port, char *text) {
    char *newPos;
    if ((text == NULL) || (*text < '0') || (*text > '9')) {
        return NULL;
    }
    *port = strtol(text, &newPos, 10);
    if (newPos == text) {
        *port = -1;
        return NULL;
    }
    if ((*port < 0) || (*port > 65535)) {
        *port = -1;
        return NULL;
    }
    return newPos;
}

// Function to check if the given IP address is valid
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

// Function to check if the given port is valid
bool isValidPort(int port) {
    return port >= 0 && port <= 65535;
}

// Reads a firewall rule from the given input string. It returns a pointer to a new
// firewallRule_t structure if the rule is successfully parsed; otherwise, it returns NULL.
// char *inputString: The input string containing the firewall rule.
struct firewallRule_t *readRule(char *inputString) {
    struct firewallRule_t *newRule;
    char *pos;
    // parse IP addresses
    newRule = malloc(sizeof(struct firewallRule_t));
    pos = parseIPaddress(newRule->ipaddr1, inputString);
    if ((pos == NULL) || (newRule->ipaddr1[0] == -1)) {
        free(newRule);
        return NULL;
    }
    if (*pos == '-') {
        // read second IP address
        pos = parseIPaddress(newRule->ipaddr2, pos + 1);
        if ((pos == NULL) || (newRule->ipaddr2[0] == -1)) {
            free(newRule);
            return NULL;
        }
        if (compareIPAddresses(newRule->ipaddr1, newRule->ipaddr2) != -1) {
            free(newRule);
            return NULL;
        }
    } else {
        newRule->ipaddr2[0] = -1;
    }
    if (*pos != ' ') {
        free(newRule);
        return NULL;
    } else
        pos++;
    // parse ports
    pos = parsePort(&(newRule->port1), pos);
    if ((pos == NULL) || (newRule->port1 == -1)) {
        free(newRule);
        return NULL;
    }
    if ((*pos == '\n') || (*pos == '\0')) {
        newRule->port2 = -1;
        return newRule;
    }
    if (*pos != '-') {
        free(newRule);
        return NULL;
    }
    pos++;
    pos = parsePort(&(newRule->port2), pos);
    if ((pos == NULL) || (newRule->port2 == -1)) {
        free(newRule);
        return NULL;
    }
    if (newRule->port2 <= newRule->port1) {
        free(newRule);
        return NULL;
    }
    if ((*pos == '\n') || (*pos == '\0')) {
        return newRule;
    }
    free(newRule);
    return NULL;
}

// Function to add a rule to the stored rules
void addRuleToStoredRules(struct firewallRules_t **rules, struct firewallRule_t *newRule) {
    struct firewallRules_t *newNode = malloc(sizeof(struct firewallRules_t));
    if (newNode == NULL) {
        // Handle memory allocation failure
        printf("Error: Memory allocation failed.\n");
        exit(EXIT_FAILURE);
    }
    // Initialize the queriedPairs list for the new rule
    newRule->queriedPairs = NULL;
    newNode->rule = newRule;
    newNode->next = *rules;
    *rules = newNode;
}


bool isValidRule(struct firewallRule_t *newRule) { // newRule is the firewallRule_t structure (ip1, ip2, port1, por2)
    // Check if IP addresses and ports are within valid ranges
    for (int i = 0; i < 4; i++) {
        if (newRule->ipaddr1[i] < 0 || newRule->ipaddr1[i] > 255 ||
            (newRule->ipaddr2[i] >= 0 && newRule->ipaddr2[i] > 255)) {
            return false;
        }
    }
    if (newRule->port1 < 0 || newRule->port1 > 65535 ||
        (newRule->port2 >= 0 && newRule->port2 > 65535)) {
        return false;
    }
    return true;
}

// Convert an IP String to an array of Integers
void convertIPStringToInt(char *ipString, int *ipArray) {
    sscanf(ipString, "%d.%d.%d.%d", &ipArray[0], &ipArray[1], &ipArray[2], &ipArray[3]);
}

char *BconvertIPArrayToString(int *ipArray, char *ipString, size_t ipStringSize) {
    snprintf(ipString, ipStringSize, "%u.%u.%u.%u", ipArray[0], ipArray[1], ipArray[2], ipArray[3]);
    return ipString;
}

// Function to list all rules and associated queries and send to the client
void listRulesAndSend(struct firewallRules_t *rules, int clientSocket) {
    const struct firewallRules_t *current = rules;
    char buffer[BUFFERLENGTH];
    char ipAddressBuffer1[BUFFERLENGTH];
    char ipAddressBuffer2[BUFFERLENGTH];
    while (current != NULL) {
        // Concatenate rule specification to buffer with null checks
        if (current->rule->ipaddr2[0] == -1) {
            if (current->rule->port2 == -1) {
                snprintf(buffer, sizeof(buffer), "Rule: %s %d\n",
                         BconvertIPArrayToString(current->rule->ipaddr1, ipAddressBuffer1, sizeof(ipAddressBuffer1)),
                         current->rule->port1);
            } else {
                snprintf(buffer, sizeof(buffer), "Rule: %s %d-%d\n",
                         BconvertIPArrayToString(current->rule->ipaddr1, ipAddressBuffer1, sizeof(ipAddressBuffer1)),
                         current->rule->port1, current->rule->port2);
            }
        } else if (current->rule->port2 == -1) {
            snprintf(buffer, sizeof(buffer), "Rule: %s-%s %d\n",
                     BconvertIPArrayToString(current->rule->ipaddr1, ipAddressBuffer1, sizeof(ipAddressBuffer1)),
                     BconvertIPArrayToString(current->rule->ipaddr2, ipAddressBuffer2, sizeof(ipAddressBuffer2)),
                     current->rule->port1);
        } else {
            snprintf(buffer, sizeof(buffer), "Rule: %s-%s %d-%d\n",
                     BconvertIPArrayToString(current->rule->ipaddr1, ipAddressBuffer1, sizeof(ipAddressBuffer1)),
                     BconvertIPArrayToString(current->rule->ipaddr2, ipAddressBuffer2, sizeof(ipAddressBuffer2)),
                     current->rule->port1, current->rule->port2);
        }
        // Send the rule to the client
        send(clientSocket, buffer, strlen(buffer), 0);
        // Concatenate and send associated queries to buffer with null checks
        struct queriedPair_t *pair = current->rule->queriedPairs;
        while (pair != NULL) {
            snprintf(buffer, sizeof(buffer), "Query: %s %d\n",
                     BconvertIPArrayToString(pair->ipaddr, ipAddressBuffer1, sizeof(ipAddressBuffer1)), pair->port);
            // Send the query to the client
            send(clientSocket, buffer, strlen(buffer), 0);
            pair = pair->next;
        }
        // Move to the next rule
        current = current->next;
    }
}


// Function to check if the IP address and port match a rule
int checkRule(struct firewallRule_t *rule, char *ipAddress, int port) {
    int ipArray[4];
    convertIPStringToInt(ipAddress, ipArray);
    // Assuming ipaddr1, ipaddr2, port1, and port2 are members of the firewallRule_t structure
    bool ipMatch = checkIPAddress(rule->ipaddr1, rule->ipaddr2, ipArray);
    int portMatch = checkPort(rule->port1, rule->port2, port);
    return (ipMatch && portMatch == 0);
}


// checkPacket checks if the IP address and port match any rule
// but also adds the IP address and port to the list of queried pairs for the matching rule.
char *checkPacket(struct firewallRules_t *rules, char *ipAddress, int port) {
    const struct firewallRules_t *current = rules;
    struct queriedPair_t *checkedQuery = NULL;
    // Search for the query in the list of queried pairs
    while (current != NULL) {
        struct queriedPair_t *pair = current->rule->queriedPairs;
        while (pair != NULL) {
            int ipArray[4];
            convertIPStringToInt(ipAddress, ipArray);
            if (compareIPAddresses(pair->ipaddr, ipArray) == 0 && pair->port == port) {
                checkedQuery = pair;
                break;
            }
            pair = pair->next;
        }
        if (checkedQuery != NULL) {
            break;  // Query found in the list, break out of the outer loop
        }
        current = current->next;
    }
    // If the query has been checked before, add it to all different rules it satisfies
    if (checkedQuery != NULL) {
        current = rules;  // Reset to the beginning of the list
        while (current != NULL) {
            // Check if the IP address and port match this rule
            if (checkRule(current->rule, ipAddress, port)) {
                // Add the query to the list
                struct queriedPair_t *newPair = malloc(sizeof(struct queriedPair_t));
                int ipArray[4];
                convertIPStringToInt(ipAddress, ipArray);
                memcpy(newPair->ipaddr, ipArray, sizeof(int) * 4);
                newPair->port = port;
                newPair->next = current->rule->queriedPairs;
                current->rule->queriedPairs = newPair;
            }
            current = current->next;
        }
        return "Connection accepted"; // (Query checked before, added to different rules which satisfies it)
    }
    // If the query has not been checked before, proceed with the regular logic
    current = rules;  // Reset to the beginning of the list
    while (current != NULL) {
        // Check if the IP address and port exactly match this rule
        if (compareIPAddresses(current->rule->ipaddr1, current->rule->ipaddr2) == 0 &&
            current->rule->port1 == current->rule->port2 &&
            current->rule->port1 == port) {
            // Add the exact match query to the list
            struct queriedPair_t *newPair = malloc(sizeof(struct queriedPair_t));
            int ipArray[4];
            convertIPStringToInt(ipAddress, ipArray);
            memcpy(newPair->ipaddr, ipArray, sizeof(int) * 4);
            newPair->port = port;
            newPair->next = current->rule->queriedPairs;
            current->rule->queriedPairs = newPair;

            return "Connection accepted"; // Exact Match
        }
        // Check if the IP address and port match this rule
        if (checkRule(current->rule, ipAddress, port)) {
            // Add the query to the list
            struct queriedPair_t *newPair = malloc(sizeof(struct queriedPair_t));
            int ipArray[4];
            convertIPStringToInt(ipAddress, ipArray);
            memcpy(newPair->ipaddr, ipArray, sizeof(int) * 4);
            newPair->port = port;
            newPair->next = current->rule->queriedPairs;
            current->rule->queriedPairs = newPair;

            return "Connection accepted";
        }
        current = current->next;
    }
    // If no matching rule is found, return appropriate message
    return "Connection rejected";
}

// Function to compare two rules
int compareRules(const struct firewallRule_t *rule1, const struct firewallRule_t *rule2) {
    if (rule1 == NULL || rule2 == NULL) {
        return -1;
    }
    for (int i = 0; i< 4; i++){
        if (rule1->ipaddr1[i] == rule2->ipaddr1[i] && (rule1->ipaddr2[i] == rule2->ipaddr2[i])){ // IPs are the same
            if (rule1->port1 == rule2->port1 && (rule1->port2 == rule2->port2)){
                return 0; // results are the same
            }
        }
    }
    return 1;  // Rules are different
}


void freeQueriedPairs(struct queriedPair_t *pair) {
    while (pair != NULL) {
        struct queriedPair_t *nextPair = pair->next;
        free(pair);
        pair = nextPair;
    }
}

char *deleteRule(struct firewallRules_t **rules, struct firewallRule_t *ruleToDelete) {
    struct firewallRules_t *current = *rules;
    struct firewallRules_t *prev = NULL;
    char found = 0;  // Flag to check if at least one rule is found and deleted
    while (current != NULL) {
        if (compareRules(current->rule, ruleToDelete) == 0) { // same rule
            // free memory queried pairs of a rule
            if (current->rule->queriedPairs != NULL) {
                freeQueriedPairs(current->rule->queriedPairs);
            }
            // Free the memory of the firewallRule_t
            free(current->rule);
            if (prev == NULL) {
                // Rule is at the beginning of the list
                *rules = current->next;
                free(current);
            } else {
                // Rule is in the middle or end of the list
                prev->next = current->next;
                free(current);
            }
            found = 1;  // Set the flag to indicate that a rule is found and deleted
            current = *rules;  // Reset current to the beginning after deletion
        } else {
            prev = current;
            current = current->next;
        }
    }
    return found ? "Rule deleted" : "Rule not found";
}


void *processRequest(void *args) {
    struct threadArgs_t *threadArgs = (struct threadArgs_t *)args;
    char buffer[BUFFERLENGTH];
    ssize_t bytesRead;

    // Read the client request
    bytesRead = read(threadArgs->newsockfd, buffer, sizeof(buffer) - 1);
    if (bytesRead <= 0) {
        perror("Error reading from socket");
        close(threadArgs->newsockfd);
        pthread_exit(NULL);
    }

    // Null-terminate the received data
    buffer[bytesRead] = '\0';

    // Process the client requests
    if (strncmp(buffer, "ADD_RULE", 8) == 0) {
        // Extract the rule from the request
        char *ruleText = buffer + 9;
        // Parse the rule
        struct firewallRule_t *newRule = readRule(ruleText);
        // Check if the rule is valid
        if (newRule != NULL && isValidRule(newRule)) {
            // Add the rule to the stored rules
            pthread_mutex_lock(&rulesMutex);
            addRuleToStoredRules(&rules, newRule);
            pthread_mutex_unlock(&rulesMutex);
            // Use write instead of send
            write(threadArgs->newsockfd, "Rule added", 11);
        } else {
            // Use write instead of send
            write(threadArgs->newsockfd, "Invalid rule", 13);
        }
    }
    else if (strncmp(buffer, "DELETE_RULE", 10) == 0) {
        // Extract the rule from the request
        char *ruleText = buffer + 12;
        // Parse the rule
        struct firewallRule_t *newRule = readRule(ruleText);
        if (newRule != NULL && isValidRule(newRule)){
            char *result = deleteRule(&rules, newRule);
            write(threadArgs->newsockfd, result, strlen(result));
            free(newRule);
        }
        else {
            // Use write instead of send
            write(threadArgs->newsockfd, "Rule invalid", 13);
        }
    }
    else if (strncmp(buffer, "CHECK_RULE", 10) == 0) {
        char ipAddress[256];
        int port;
        // Use sscanf to extract IP address and port from the command
        if (sscanf(buffer, "CHECK_RULE %s %d", ipAddress, &port) == 2) {
            char inputString[512];
            snprintf(inputString, sizeof(inputString), "%s %d", ipAddress, port);
            struct firewallRule_t *parsedRule = readRule(inputString);
            if (parsedRule != NULL) {
                char *result = checkPacket(rules, ipAddress, port);
                // Use write instead of send
                write(threadArgs->newsockfd, result, strlen(result));
                free(parsedRule);
            }
        } else {
            // Handle invalid command format
            // Use write instead of send
            write(threadArgs->newsockfd, "Illegal request", strlen("Illegal request"));
        }
    }
    else if (strncmp(buffer, "LIST_RULES", 9) == 0) {
        // Use write instead of send
        listRulesAndSend(rules, threadArgs->newsockfd);
    }
    else {
        // Unknown request, send an appropriate response
        send(threadArgs->newsockfd, "Illegal request\n", 16, 0);
    }
    // Close the client socket
    close(threadArgs->newsockfd);

    // Signal that the thread has finished its task
    pthread_mutex_lock(&threadEndLock);
    serverThreads[threadArgs->threadIndex].status = THREAD_FINISHED;
    pthread_cond_signal(&threadCond);
    pthread_mutex_unlock(&threadEndLock);

    pthread_exit(NULL);
}


int main(int argc, char *argv[])
{

    socklen_t clilen;
    int sockfd, portno;
    struct sockaddr_in6 serv_addr, cli_addr;
    int result;
    pthread_t waitInfo;
    pthread_attr_t waitAttributes;

    if (argc < 2) {
        fprintf (stderr,"ERROR, no port provided\n");
        exit(1);
    }

    /* create socket */
    sockfd = socket (AF_INET6, SOCK_STREAM, 0);
    if (sockfd < 0)
        error("ERROR opening socket");
    bzero ((char *) &serv_addr, sizeof(serv_addr));
    portno = atoi(argv[1]);
    serv_addr.sin6_family = AF_INET6;
    serv_addr.sin6_addr = in6addr_any;
    serv_addr.sin6_port = htons (portno);
    /* bind it */
    if (bind(sockfd, (struct sockaddr *) &serv_addr,
             sizeof(serv_addr)) < 0)
        error("ERROR on binding");
    /* ready to accept connections */
    listen (sockfd,5);
    clilen = sizeof (cli_addr);
    /* create separate thread for waiting  for other threads to finish */
    if (pthread_attr_init (&waitAttributes)) {
        fprintf (stderr, "Creating initial thread attributes failed!\n");
        exit (1);
    }
    result = pthread_create (&waitInfo, &waitAttributes, waitForThreads, NULL);
    if (result != 0) {
        fprintf (stderr, "Initial Thread creation failed!\n");
        exit (1);
    }
    /* now wait in an endless loop for connections and process them */
    while(1) {
        struct threadArgs_t *threadArgs; /* must be allocated on the heap to prevent variable going out of scope */
        int threadIndex;

        threadArgs = malloc(sizeof(struct threadArgs_t));
        if (!threadArgs) {
            fprintf (stderr, "Memory allocation failed!\n");
            exit (1);
        }

        /* waiting for connections */
        threadArgs->newsockfd = accept( sockfd,
                                        (struct sockaddr *) &cli_addr,
                                        &clilen);
        if (threadArgs->newsockfd < 0)
            error ("ERROR on accept");

        /* create thread for processing of connection */
        threadIndex =findThreadIndex();
        threadArgs->threadIndex = threadIndex;
        if (pthread_attr_init (&(serverThreads[threadIndex].attributes))) {
            fprintf (stderr, "Creating thread attributes failed!\n");
            exit (1);
        }
        result = pthread_create (&(serverThreads[threadIndex].pthreadInfo), &(serverThreads[threadIndex].attributes), processRequest, (void *) threadArgs);
        if (result != 0) {
            fprintf (stderr, "Thread creation failed!\n");
            exit (1);
        }
    }
}