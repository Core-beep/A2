#include <stdlib.h>
#include <stdio.h>
#include <math.h>
#include <netdb.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <string.h>
#include <time.h>

#ifdef __APPLE__
#include "./endian.h"
#else
#include <endian.h>
#endif

#include "./peer.h"


//-----------------------------------     <- Beginning of code
//...................................     <- end of code




// Global variables to be used by both the server and client side of the peer.
Address_t *my_address;

Address_t** network = NULL;
uint32_t peer_count = 0;

//-----------------------------------------------------------------------------------------------
/*
Protects the shared network list and peer count.
Only one thread may modify or inspect thisdata
while holding the mutex.
*/
pthread_mutex_t network_mutex = PTHREAD_MUTEX_INITIALIZER;

// Lock for network and peer_count, which are used by both the client thread
// and the server threads. It must be held whenever either is read or changed.
pthread_mutex_t network_mutex = PTHREAD_MUTEX_INITIALIZER;

// How much data fits in a single reply message after its header
static const uint32_t MAX_PAYLOAD = MAX_MSG_LEN - REPLY_HEADER_LEN;
//................................................................................................

/*
Reusable signature function for salting signatures, takes 4 arguments: password we want to hash, how many bytes password is,
 salt to combine with passwrd, where signature is stored (my_address).
*/
//-----------------------------------------------------------------------------------------------
void get_signature(const char *password, int password_len, const char *salt, hashdata_t hash) {
    char salted_input[2 * PASSWORD_LEN + 2 * SALT_LEN + 16];

    int input_length = snprintf(
        salted_input,
        sizeof(salted_input),
        "b'%.*s'b'%.*s'",
        password_len, password,
        SALT_LEN,
        salt
    );

    if (input_length < 0 || (size_t)input_length >= sizeof(salted_input)) {
        fprintf(stderr, "Failed to salt password!\n");
        exit(EXIT_FAILURE);
    }

    get_data_sha(salted_input, hash, (uint32_t)input_length, SHA256_HASH_SIZE);
}

//................................................................................................

/*
 * Find a peer in the network by its address. Returns NULL if it is not known.
 * The caller must hold network_mutex.
 */
Address_t* find_peer(char *ip, uint32_t port)
{
    for (uint32_t i=0; i<peer_count; i++)
    {
        if (network[i]->port == port && strncmp(network[i]->ip, ip, IP_LEN) == 0)
        {
            return network[i];
        }
    }
    return NULL;
}

/*
 * Add a peer to the network unless it is already there, so the network never
 * holds duplicates.
 */
void add_peer(char *ip, uint32_t port, uint8_t *signature, char *salt)
{
    // Ignore addresses that could not be connected to anyway
    if (port > 65535 || strnlen(ip, IP_LEN) == IP_LEN)
    {
        return;
    }

    Address_t *peer = find_peer(ip, port);
    if (peer == NULL)
    {
        peer = calloc(1, sizeof(Address_t));
        strncpy(peer->ip, ip, IP_LEN);
        peer->port = port;
        network = realloc(network, (peer_count+1) * sizeof(Address_t*));
        network[peer_count] = peer;
        peer_count++;
    }
    if (signature != NULL && peer->salt[0] == '\0')
    {
        memcpy(peer->signature, signature, SHA256_HASH_SIZE);
        memcpy(peer->salt, salt, SALT_LEN);
    }
}


/*
 * Reads the reply to a request. Each block is checked against its hash, and
 * all of them together against the total hash. It returns the status code of
 * the reply and gives its body in *data or 0 if no valid reply could be read.
 */
uint32_t read_reply(compsys_helper_state_t *state, char **data,
    uint32_t *length)
{
    ReplyHeader_t reply_header;
    hashdata_t hash;
    char *body = NULL;
    uint32_t block_count = 1;
    uint32_t received = 0;
    *data = NULL;
    *length = 0;

    while (received < block_count && compsys_helper_readnb(state,&reply_header, REPLY_HEADER_LEN) == REPLY_HEADER_LEN)
    {
        uint32_t block_length = ntohl(reply_header.length);
        uint32_t this_block = ntohl(reply_header.this_block);

        if (body == NULL)
        {
            block_count = ntohl(reply_header.block_count);
            body = calloc((size_t)block_count * MAX_PAYLOAD + 1, 1);
        }
        if (body == NULL || this_block >= block_count || block_length > MAX_PAYLOAD)
        {
            break;
        }

        // The block number tells us where a block belongs no matter what order the blocks arrive in
        char *block = body + (size_t)this_block * MAX_PAYLOAD;
        if (compsys_helper_readnb(state, block, block_length) != block_length)
        {
            break;
        }
        get_data_sha(block, hash, block_length, SHA256_HASH_SIZE);
        if (memcmp(hash, reply_header.block_hash, SHA256_HASH_SIZE) != 0)
        {
            break;
        }

        *length += block_length;
        received++;
    }

    if (body != NULL)
    {
        get_data_sha(body, hash, *length, SHA256_HASH_SIZE);
    }
    if (body == NULL || received == 0 || received < block_count || memcmp(hash, reply_header.total_hash, SHA256_HASH_SIZE) != 0)
    {
        free(body);
        return 0;
    }

    *data = body;
    return ntohl(reply_header.status);
}


/*
 * Send a request message to another peer on the network. Unless this is 
 * specifically an 'inform' message as described in the assignment handout, a 
 * reply will always be expected.
 */
void send_message(Address_t peer_address, int command, 
    char* request_body, int body_length)
{
    fprintf(stdout, "Connecting to server at %s:%d to run command %d\n", 
        peer_address.ip, peer_address.port, command);

    compsys_helper_state_t state;
    char msg_buf[MAX_MSG_LEN];
    FILE* fp;

    // Setup connection. Note that we need to convert our port from an integer
    // to a string
    char port_char[6];
    port_char[5] = '\0';
    sprintf(port_char, "%d", peer_address.port);
    int peer_socket = compsys_helper_open_clientfd(peer_address.ip, port_char);
    compsys_helper_readinitb(&state, peer_socket);

    // Construct a request message and send it to the peer
    struct RequestHeader request_header;
    strncpy(request_header.ip, my_address->ip, IP_LEN);
    memcpy(my_address->signature, request_header.signature, SHA256_HASH_SIZE);
    request_header.port = htonl(my_address->port);
    request_header.command = htonl(command);
    request_header.length = htonl(body_length);
    // Copy the header and body together to the message buffer, then write to 
    // the socket
    memcpy(msg_buf, &request_header, REQUEST_HEADER_LEN);
    memcpy(msg_buf+REQUEST_HEADER_LEN, request_body, body_length);
    compsys_helper_writen(peer_socket, msg_buf, REQUEST_HEADER_LEN+body_length);

    /*
    3: Handing the response to the register message
    Rather than closing immediately we should probably handle a response.
    */
    if (command != COMMAND_INFORM)
    {
        char *reply;
        uint32_t reply_length;
        uint32_t status = read_reply(&state, &reply, &reply_length);

        if (command == COMMAND_REGISTER && (status == STATUS_OK || status == STATUS_PEER_EXISTS))
        {

            pthread_mutex_lock(&network_mutex);
            for (uint32_t i=0; i+PEER_ADDR_LEN<=reply_length; i+=PEER_ADDR_LEN)
            {
                Address_t entry;
                memcpy(&entry, reply+i, PEER_ADDR_LEN);
                add_peer(entry.ip, ntohl(entry.port), entry.signature,
                    entry.salt);
            }
            add_peer(peer_address.ip, peer_address.port, NULL, NULL);
            printf("Registered with status %d, network has %d peers\n", status,
                peer_count);
            pthread_mutex_unlock(&network_mutex);
        }
        else if (command == COMMAND_RETREIVE && status == STATUS_OK)
        {
            // We write to a temporary file, so server threads can never serve a file that is only half written
            char temp_path[PATH_LEN+8];
            sprintf(temp_path, "%s.part", request_body);
            fp = fopen(temp_path, "wb");
            if (fp == NULL)
            {
                printf("Couldn't write to %s\n", temp_path);
            }
            else
            {
                fwrite(reply, 1, reply_length, fp);
                fclose(fp);
                rename(temp_path, request_body);
                printf("Retrieved data written to %s\n", request_body);
            }
        }
        else
        {
            printf("Status %d: %s\n", status, reply == NULL ? "no reply" : reply);
        }
        free(reply);
    }

    close(peer_socket);
}

/*
 * Function to act as thread for all required client interactions. This thread 
 * will be run concurrently with the server_thread. It will start by requesting
 * the IP and port for another peer to connect to. Once both have been provided
 * the thread will register with that peer and expect a response outlining the
 * complete network. The user will then be prompted to provide a file path to
 * retrieve. This file request will be sent to a random peer on the network.
 * This request/retrieve interaction is then repeated forever.
 */ 
void* client_thread()
{
    char peer_ip[IP_LEN];
    fprintf(stdout, "Enter peer IP to connect to: ");
    scanf("%16s", peer_ip);

    // Clean up password string as otherwise some extra chars can sneak in.
    for (int i=strlen(peer_ip); i<IP_LEN; i++)
    {
        peer_ip[i] = '\0';
    }

    char peer_port[PORT_STR_LEN];
    fprintf(stdout, "Enter peer port to connect to: ");
    scanf("%16s", peer_port);

    // Clean up password string as otherwise some extra chars can sneak in.
    for (int i=strlen(peer_port); i<PORT_STR_LEN; i++)
    {
        peer_port[i] = '\0';
    }

    Address_t peer_address;
    memcpy(peer_address.ip, peer_ip, IP_LEN);
    peer_address.port = atoi(peer_port);

    /*
    2: Sending a first register message
    Here you should probably send a first register message using the 
    send_message function.
    */
    send_message(peer_address, COMMAND_REGISTER, "", 0);

    // Repeatedly ask for a file, and request it from a random peer
    srand(time(NULL));
    while (1)
    {
        char path[PATH_LEN];
        printf("Type the name of a file to be retrieved, or 'quit' to quit:\n");
        if (scanf("%127s", path) != 1)
        {
            return NULL;
        }
        if (strcmp(path, "quit") == 0)
        {
            exit(EXIT_SUCCESS);
        }

        // Pick who are first in the network, but not ourselves. Copies the address so the lock is not held while we talk to the peer.
        pthread_mutex_lock(&network_mutex);
        if (peer_count < 2)
        {
            pthread_mutex_unlock(&network_mutex);
            printf("There are no other peers to ask\n");
            continue;
        }
        peer_address = *network[1 + rand() % (peer_count-1)];
        pthread_mutex_unlock(&network_mutex);

        send_message(peer_address, COMMAND_RETREIVE, path, strlen(path));
    }

    // You should never see this printed in your finished implementation
    printf("Client thread done\n");

    return NULL;
}


//-----------------------------------------------------------------------------------------------
/*
Check wether a peeralready exists in our network.

Parameters:
ip - IP adress of the peer
port - Port number of the peer.

Returns: 1 if the peer exists, 0 otherwise.

Important the caller must hold network mutex.
*/
int peer_exists(const char *ip, uint32_t port) {
    
    // Examine every peer currently stored in network
    for (uint32_t i = 0; i < peer_count; i++) {

        // Check both IP adress and port
        if (strcmp(network[i]->ip, ip) === 0 && network[i]->port == port) {
            return 1;
        }
    }

    // If no matching peer was found
    return 0;
}
//....................................................................................................




//-----------------------------------------------------------------------------------------------
/*
 Handle one incoming connection from another peer.

 Reads the request header, extracts it's fields and reads
 the request body, if tere is one.

 Parameter: vargp, a pointer to the accepted connection descriptor
 Returns: NULL, when the conection has been handled.
 */
void* handle_server_request_thread(void *vargp)
{
    // Get the connection descriptor passed by the server thread.
    int connfd = *((int *)vargp);

    // Detatch the thread and free the allocated argument.
    pthread_detach(pthread_self());
    free(vargp);

    // Set up the buffered socket reader.
    compsys_helper_state_t state;
    compsys_helper_readinitb(&state, connfd);

    // Read the fixed size request header (total of 60 bytes)
    char header_buf[REQUEST_HEADER_LEN];

    ssize_t bytes_read = compsys_helper_readnb(&state, header_buf, REQUEST_HEADER_LEN);

    if (bytes_read != REQUEST_HEADER_LEN) {
        fprintf(stderr, "Failed to read request header \n");
        close(connfd);
        return NULL;
    }

    // Extract the fields from the recieved header
    RequestHeader_t request;

    memcpy(request.ip, header_buf, IP_LEN);

    // Store IP iun a null-terminated buffer for safe printing.
    char sender_ip[IP_LEN + 1];
    memcpy(sender_ip, request.ip, IP_LEN);
    sender_ip[IP_LEN] = '\0';

    //Numeric values are transmitted in network byte order.
    uint32_t number;

    memcpy(&number, header_buf + 16, sizeof(number));
    request.port = ntohl(number);

    memcpy(request.signature, header_buf + 20, SHA256_HASH_SIZE);

    memcpy(&number, header_buf + 52, sizeof(number));
    request.command = ntohl(number);

    memcpy(&number, header_buf + 56, sizeof(number));
    request.length = ntohl(number);


    // Check that the command is one of the defined types.
    if (request.command < COMMAND_REGISTER || request.command > COMMAND_INFORM) {
        fprintf(stderr, "Invalid request command! \n");
        close(connfd);
        return NULL;
    }


    // make sure the request body fits our own buffer
    if (request.length > MAX_MSG_LEN - REQUEST_HEADER_LEN) {
        fprintf(stderr, "Request body too large! \n");
        close(connfd);
        return NULL;
    }


    // Read the body, body may be 0 bytes also.
    char body[MAX_MSG_LEN - REQUEST_HEADER_LEN + 1];

    if (request.length > 0) {
        bytes_read = compsys_helper_readnb(&state, body, request.length);

        if (bytes_read != (ssize_t)request.length) {
            fprintf(stderr, "Failed to read request body! \n");
            close(connfd);
            return NULL;
        }
    }

    // Extra terminator for debugging as text.
    body[request.length] = '\0';

    // Temporary output to verify that parsing works.
    printf("Recieved request: \n");
    printf("  IP: %s \n", sender_ip);
    printf("  Port: %u \n", request.port);
    printf("  Command: %u \n", request.command);
    printf("  Body length: %u \n", request.length);

    
    /*
    First stage of registration handling:

    validate the incoming peer and check for duplicates.

    Actual registration and respone to follow..
    */

    if (request.command == COMMAND_REGISTER) {

        // Registration request must have an empty body
        if (request.length != 0) {
            fprintf(stderr, "Invalid registration body! \n");
        } else if(!is_valid_ip(sender_ip) || !is_valid_port(request.port) || request.port == 0) {
            fprintf(stderr, "Invalid registering peer adress \n");
        } else {
            // protect nbetwork while checking its contents
            pthread_mutex_lock(&network_mutex);

            if (peer_exists(sender_ip, request.port)) {
                printed("Peer %s:%u already exists \n", sender_ip, request.port);
            } else {
                printf("New pper detected: %s:%u \n", sender_ip, request.port);

                //Next: generate the peer's network signature
                // and insert it into the network list.
            }

            pthread_mutex_unlock(&network_mutex);
        }
    }
    
    

    close(connfd);
    return NULL;


}

//....................................................................................................

/*
 * Function to act as basis for running the server thread. This thread will be
 * run concurrently with the client thread, but is infinite in nature.
 */
void* server_thread()
{
    int listenfd; // file descriptor. Used to identify an open resource, such as a socket.
    
    // Start listening
    char port_char[6];
    port_char[5] = '\0';
    sprintf(port_char, "%d", my_address->port);
    listenfd = compsys_helper_open_listenfd(port_char);
    
    printf("Starting to listen on %s:%d\n", my_address->ip, my_address->port);
    
    /*
    4: Setting Up Server Threading
    Here we should implement some sort of loop to accept inbound communications
    and handle them within a thread so they do not block subsequent 
    connections. The function 'handle_server_request_thread' has been provided
    as a simple skeleton function you could use to process your requests in.
    */

    //-----------------------------------------------------------------------------------------------
    /*
    Continuously accepts connection from other peer.
    Each connection is handled by a seperate thread so that the
    server can accept new connections whil etheothers are processed.
    */

    while (1) {

        // Allocate memory for the new connection's file descriptor
        // Each handler thread needs its own copy
        int * connfd = malloc(sizeof(int));

        if (connfd == NULL) {
            perror("malloc failed");
            continue;
        }

        // Wait for another peer to connect
        *connfd = accept(listenfd, NULL, NULL); // returns a new file descriptor representing that particular connection.

        if (*connfd < 0) {
            perror("accept failed");
            free(connfd);
            continue;
        }


        // Create a thread to handle this connection
        pthread_t thread_id;

        if (pthread_create(&thread_id, NULL, handle_server_request_thread, connfd) != 0) {
            perror("pthread_create failed");
            close(*connfd);
            free(connfd);
        }
    }
    //....................................................................................................



    // You should never see this printed in your finished implementation
    printf("Server thread done\n");

    return NULL;
}


int main(int argc, char **argv)
{
    // Users should call this script with a single argument describing what 
    // config to use
    if (argc != 3)
    {
        fprintf(stderr, "Usage: %s <IP> <PORT>\n", argv[0]);
        exit(EXIT_FAILURE);
    } 

    my_address = (Address_t*)malloc(sizeof(Address_t));
    memset(my_address->ip, '\0', IP_LEN);
    memcpy(my_address->ip, argv[1], strlen(argv[1]));
    my_address->port = atoi(argv[2]);

    if (!is_valid_ip(my_address->ip)) {
        fprintf(stderr, ">> Invalid peer IP: %s\n", my_address->ip);
        exit(EXIT_FAILURE);
    }
    
    if (!is_valid_port(my_address->port)) {
        fprintf(stderr, ">> Invalid peer port: %d\n", 
            my_address->port);
        exit(EXIT_FAILURE);
    }

    char password[PASSWORD_LEN];
    fprintf(stdout, "Create a password to proceed: ");
    scanf("%16s", password);

    // Clean up password string as otherwise some extra chars can sneak in.
    for (int i=strlen(password); i<PASSWORD_LEN; i++)
    {
        password[i] = '\0';
    }

    // Most correctly, we should randomly generate our salts, but this can make
    // repeated testing difficult so feel free to use the hard coded salt below
    char user_salt[SALT_LEN+1] = "0123456789ABCDEF";                             // Removed "\0" from "..EF\0".
    //generate_random_salt(user_salt);
    memcpy(my_address->salt, user_salt, SALT_LEN);

    /* 
    1: Setting Up
    After determining our salt but before saving our address we should probably
    work out what our signature should be. 
    */

    //------------------------------------------------------------------------------------------
    get_signature(password, strlen(password), my_address->salt, my_address->signature);


    // Test by printing generated signature as hexadecimal characters
    printf("Gernerated signature: ");

    for (int i = 0; i < SHA256_HASH_SIZE; i++) {
        printf("%02x", my_address->signature[i]);
    }

    printf("\n");

    //..........................................................................................





    // Start our record of the network by recording our own address. Make sure
    // any time we update this array we also update the peer_count.
    network = malloc(sizeof(Address_t*));
    network[0] = my_address;
    peer_count = 1;

    // Setup the client and server threads 
    pthread_t client_thread_id;
    pthread_t server_thread_id;
    pthread_create(&client_thread_id, NULL, client_thread, NULL);
    pthread_create(&server_thread_id, NULL, server_thread, NULL);

    // Wait for them to complete. 
    pthread_join(client_thread_id, NULL);
    pthread_join(server_thread_id, NULL);

    exit(EXIT_SUCCESS);
}