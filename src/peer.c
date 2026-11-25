#include <stdlib.h>
#include <stdio.h>
#include <math.h>
#include <netdb.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <string.h>
#include <time.h>
#include <limits.h>

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
// Lock for network and peer_count, which are used by both the client thread
// and the server threads. It must be held whenever either is read or changed.
pthread_mutex_t network_mutex = PTHREAD_MUTEX_INITIALIZER;

// How much data fits in a single reply message after its header
static const uint32_t MAX_PAYLOAD = MAX_MSG_LEN - REPLY_HEADER_LEN;
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


//-----------------------------------------------------------------------------------------------
/*
Append a byte array using python's bytes representation.

ex: hello -> b'hello'

Binary bytes are escaped as needed.

returns 1 on success, 0 if the buffer is too small.
*/

int append_python_bytes(char *out, size_t capacity, size_t *pos, const uint8_t *data, size_t length) {
    const char hex[] = "0123456789abcdef";
    int has_single = 0;
    int has_double = 0;

    // Python prefers double quotes when data contain single quotes but no double quotes.
    for (size_t i = 0; i < length; i++) {
        if (data[i] == '\'') has_single = 1;
        if (data[i] == '"') has_double = 1;
    }

    char quote = (has_single && !has_double) ? '"' : '\'';

    if (*pos + 2 >= capacity) return 0;
    out[(*pos)++] = 'b';
    out[(*pos)++] = quote;

    for (size_t i = 0; i < length; i++) {
        uint32_t c = data[i];
        char escaped[4];
        size_t n = 0;

        if (c == '\\' || c == (uint8_t)quote) {
            escaped[0] = '\\';
            escaped[1] = c == '\n' ? 'n' : c == '\r' ? 'r' : 't';

            n = 2;
        } else if (c >= 32 && c <= 126) {
            escaped[0] = (char)c;
            n = 1;
        } else {
            escaped[0] = '\\';
            escaped[1] = 'x';
            escaped[2] = hex[c >> 4];
            escaped[3] = hex[c & 15];
            n = 4;
        }

        if (*pos + n + 1 >= capacity) return 0;
        memcpy(out + *pos, escaped, n);
        *pos += n;
    }

    out[(*pos)++] = quote;
    out[*pos] = '\0';
    return 1;
}



/*
Generate a SHA-256 signature from data and a 16-byte salt.

Parameters:
data -     password or binary user signature.
data_len - number of bytesn in data.
salt -     16-byte salt.
hash -     destination fot the resulting 32-byte hash.

Matches the supplied python assemble_signature().
*/

void get_signature(const void *data, size_t data_len, const char *salt, hashdata_t hash) {
    char salted_input[4 * (SHA256_HASH_SIZE + SALT_LEN) + 8];
    size_t length = 0;

    if (data_len > SHA256_HASH_SIZE || !append_python_bytes(salted_input, sizeof(salted_input), &length, data, data_len) || !append_python_bytes(salted_input, sizeof(salted_input), &length, (const uint8_t *)salt, SALT_LEN)){
        fprintf(stderr, "Failed to construct salted input \n");
        exit(EXIT_FAILURE);
    }
    
    get_data_sha(salted_input, hash, (uint32_t)length, SHA256_HASH_SIZE);
}

//................................................................................................




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

    if (peer_socket < 0) {
        fprintf(stderr, "Could not connect to peer %s:%u \n", peer_address.ip, peer_address.port);
        return;
    }

    compsys_helper_readinitb(&state, peer_socket);

    // Construct a request message and send it to the peer
    struct RequestHeader request_header;
    strncpy(request_header.ip, my_address->ip, IP_LEN);
    memcpy(request_header.signature, my_address->signature, SHA256_HASH_SIZE); // reversed header and adress. 
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
    fprintf(stdout, "Enter peer IP to connect to: \n ");
    scanf("%16s", peer_ip);

    // Clean up password string as otherwise some extra chars can sneak in.
    for (int i=strlen(peer_ip); i<IP_LEN; i++)
    {
        peer_ip[i] = '\0';
    }

    char peer_port[PORT_STR_LEN];
    fprintf(stdout, "Enter peer port to connect to: \n");
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



/*
Send a single-block response to another peer.

Parameters:

connfd           - OPen socket to the requesting peer
status           - Response status, such as STATUS_OK
response_body    - Data to send after the header
response_length  - Number of bytes in the body

The 80 byte reply header contains: 
length, status, block number, number of blocks, block hash, total hash.
*/

void send_response(int connfd, uint32_t status, const char *response_body, uint32_t response_length) {
    //One message cannot exceed the maximum protocol size.
    if (response_length > MAX_MSG_LEN - REPLY_HEADER_LEN) {
        fprintf(stderr, "Response body too large! \n");
        return;
    }

    ReplyHeader_t reply;

    // Convert all numerical fields to network byte order
    reply.length = htonl(response_length);
    reply.status = htonl(status);

    // This is the first and only block
    reply.this_block = htonl(0);
    reply.block_count = htonl(1);


    /*
    Calculate the SHA-256 chacksum of the response body.

    Since we only send one block, the block hash and total has are identical.
    */

    get_data_sha(response_body, reply.block_hash, response_length, SHA256_HASH_SIZE);

    memcpy(reply.total_hash, reply.block_hash, SHA256_HASH_SIZE);

    // First send the fixed size reply header
    compsys_helper_writen(connfd, &reply, REPLY_HEADER_LEN);

    // Send the the variable length response body
    if (response_length > 0) {
        compsys_helper_writen(connfd, response_body, response_length);
    }


}



/*
Handle s amall file retrieval request.

Only files inside the peer's current working directory
can be served. FIles must fit in one response block

Parameters:

connfd  - Socket connected to the requestin gpeer.
body    - Request body containing the filename.
length  - Number of bytes in the request body.
*/

void handle_retrieve(int connfd, const char *body, uint32_t length){

    char filename[PATH_LEN];
    char root[PATH_MAX];
    char resolved[PATH_MAX];

    // ensure the filename is present and fist in our buffer.
    if (length == 0 || length >= PATH_LEN || memchr(body, '\0', length) != NULL) {
        const char *error = "Invalid filename! \n";
        send_response(connfd, STATUS_BAD_REQUEST, error, strlen(error));

        return;
    }

    // Make a null terminated copy of the filename.
    memcpy(filename, body, length);
    filename[length] = '\0';

    // Only accept relative paths
    if (filename[0] == '/') {
        const char *error = "Absolute paths not allowed! \n";
        send_response(connfd, STATUS_BAD_REQUEST, error, strlen(error));

        return;
    }


    /*
    Find the files actual location

    realpath() also resolves ../ and symbolic lnks
    so we can check that he file stays in our directory
    */

    if (realpath(".", root) == NULL || realpath(filename, resolved) == NULL) {
        const char *error = "File not found.. \n";
        send_response(connfd, STATUS_BAD_REQUEST, error, strlen(error));

        return;
    }


    // ensure the resolved path is inside our directory.
    size_t root_len = strlen(root);

    if (strncmp(resolved, root, root_len) != 0 || (resolved[root_len] != '/' && !(root_len == 1 && root[0] == '/'))) {
        const char *error = "Access denied! \n";
        send_response(connfd, STATUS_BAD_REQUEST, error, strlen(error));

        return;
    }

    // OPen the file in binary mode.
    FILE *fp = fopen(resolved, "rb");

    if (fp == NULL) {
        const char *error = "Cannot open file.. \n";
        send_response(connfd, STATUS_BAD_REQUEST, error, strlen(error));

        return;
    }

    // Determine file size
    if (fseek(fp, 0, SEEK_END) != 0) {
        fclose(fp);
        send_response(connfd, STATUS_OTHER, "Cannot read file! \n", 16);
        
        return;
    }


    long file_size = ftell(fp);

    // A single reply contains at most this many data bytes.
    const size_t max_payload = MAX_MSG_LEN - REPLY_HEADER_LEN;

    if ( file_size < 0 || (unsigned long)file_size > max_payload) {
        fclose(fp);
        const char *error = "File too large \n";
        send_response(connfd, STATUS_OTHER, error, strlen(error));

        return;
    }

    rewind(fp);

    // Read the file contents into memory.
    char file_data[MAX_MSG_LEN - REPLY_HEADER_LEN];

    size_t bytes_read = fread(file_data, 1, (size_t)file_size, fp);

    fclose(fp);

    if (bytes_read != (size_t)file_size) {
        const char *error = "Failed to read file! \n";
        send_response(connfd, STATUS_OTHER, error, strlen(error));

        return;
    }

    // Send the file contents with a successfull status
    send_response(connfd, STATUS_OK, file_data, (uint32_t)bytes_read);

    printf("Served file: %s (%zu bytes) \n", filename, bytes_read);


}







/*
Create body of a registration respone

Each peer occupies PEER_ADDR_LEN (68) bytes

the caller must hold network_mutex because ths function reads the shared network list.

returns number of bytes written, or -1 if the complete network doesn't fit in one block
*/

int build_network_response(char *buffer, size_t capacity) {
    size_t position = 0;

    for (uint32_t i = 0; i < peer_count; i++) {

        Address_t *peer = network[i];

        // Check that next entry fits in the buffer
        if (capacity - position < PEER_ADDR_LEN) {
            return -1;
        }


        // 16 bytes: IP adress
        memcpy(buffer + position, peer->ip, IP_LEN);
        position += IP_LEN;

        // 4 bytes: port in network byte order
        uint32_t port = htonl(peer-> port);
        memcpy(buffer + position, &port, PORT_LEN);
        position += PORT_LEN;

        // 32 bytes: network signature
        memcpy(buffer + position, peer->signature, SHA256_HASH_SIZE);
        position += SHA256_HASH_SIZE;

        // 16 bytes: salt.
        memcpy(buffer + position, peer->salt, SALT_LEN);
        position += SALT_LEN;
    }

    return (int)position;
}




/*
Inform all existing peer about the newly registered peer

New peer's adress, network signature and salt
must be sent in the 68 byte INFORM requst body

must not contact itself or the new peer
must not hold network mutex while sending messages.
*/

void inform_existingP(const Address_t *new_peer) {
    char inform_body[PEER_ADDR_LEN];
    size_t position = 0;

    // Build the 68 byte INFORM body
    memcpy(inform_body + position, new_peer->ip, IP_LEN);
    position += IP_LEN;

    uint32_t port = htonl(new_peer->port);
    memcpy(inform_body + position, &port, PORT_LEN);
    position += PORT_LEN;

    memcpy(inform_body + position, new_peer->signature, SHA256_HASH_SIZE);
    position += SHA256_HASH_SIZE;

    memcpy(inform_body + position, new_peer->salt, SALT_LEN);

    /*
    COpy the recipients while holding the mutex

    must not keep pointers into network because
    another thread could resize the network array.
    */

    pthread_mutex_lock(&network_mutex);

    Address_t *recipients = calloc(peer_count, sizeof(Address_t));

    if (recipients == NULL) {
        pthread_mutex_unlock(&network_mutex);
        fprintf(stderr, "Could not allocate INFORM recipients \n");
        return;
    }

    uint32_t recipient_count = 0;
    const char empty_salt[SALT_LEN] = {0};

    for (uint32_t i = 0; i < peer_count; i++) {
        Address_t *peer = network[i];

        // Don't inform self
        if (strcmp(peer->ip, my_address->ip) == 0 && peer->port == my_address->port) {
            continue;
        }

        // Don't inform the newly registered peer.
        if (strcmp(peer->ip, new_peer->ip) == 0 && peer->port == new_peer->port) {
            continue;
        }

        // Skip peers with no stored network salt.
        if (memcmp(peer->salt, empty_salt, SALT_LEN) == 0) {
            continue;
        }

        // Copy the entry instead of keeping a shared pointer
        recipients[recipient_count++] = *peer;
    }

    pthread_mutex_unlock(&network_mutex);


    /*
    Send each INFORM without holding the mutex.
    Socket operations may block
    */
    for (uint32_t i = 0; i < recipient_count; i++) {
        printf("Informing %s:%u about %s:%u \n", recipients[i].ip, recipients[i].port, new_peer->ip, new_peer->port);

        send_message(recipients[i], COMMAND_INFORM, inform_body, PEER_ADDR_LEN);

    }

    free(recipients);
}







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

        // A registration request must have an empty body
        // and contain a valid peer adress
        if (request.length != 0 || !is_valid_ip(sender_ip) || !is_valid_port(request.port) || request.port == 0) {

            fprintf(stderr, "Invalid registration request \n");
            const char *error = "invalid registration request";

            send_response(connfd, STATUS_BAD_REQUEST, error, (uint32_t)strlen(error));
        } else {
            
            /*
            Generate the network salt and signature.

            The recieved user signature us hashed again using a new salt before 
            being stored in the network list
            */
            char network_salt[SALT_LEN];
            hashdata_t network_signature;

            generate_random_salt(network_salt); // from common,

            get_signature(request.signature, SHA256_HASH_SIZE, network_salt, network_signature);


            char response_body[MAX_MSG_LEN - REPLY_HEADER_LEN];
            int response_length;
            uint32_t status = STATUS_OK;

            // Protect both the registration and network 
            
            // Remember wether this is genuinly a new registration
            int newly_registered = 0;
            //Local copy of the pee we may need to announce
            Address_t new_peer_info;


            pthread_mutex_lock(&network_mutex);

            if (find_peer(sender_ip, request.port) != NULL) {
                printf("Peer %s:%u already exists. \n", sender_ip, request.port);

                status = STATUS_PEER_EXISTS;

            } else {
                add_peer(sender_ip, request.port, network_signature, network_salt);

                printf("Registered peer %s:%u \n", sender_ip, request.port);

                // Keep copy to use after releasing the mutex.
                Address_t *added = find_peer(sender_ip, request.port);

                if (added != NULL) {
                    new_peer_info = *added;
                    newly_registered = 1;
                }
            }

            // COPy the complete network into the response buffer.
            response_length = build_network_response(response_body, sizeof(response_body));
            
            pthread_mutex_unlock(&network_mutex);



            /*
            Send the response after releasing the mutex.
            Socket operations can block so we don't want to hold network lock while sending.
            */
            if (response_length >= 0) {
                send_response(connfd, status, response_body, (uint32_t)response_length);

                printf("Registration response sent! \n");

                printf("DEBUG: newly_registered = %d \n", newly_registered);

                // Notify the existing network only about new peers.
                if (newly_registered) {
                    printf("DEBUG: Calling inform_existingP() \n");

                    inform_existingP(&new_peer_info);
                }
            } else {
                const char *error = "Network list too large!";

                send_response(connfd, STATUS_OTHER, error, (uint32_t)strlen(error));
            }
        }
    } else if (request.command == COMMAND_RETREIVE) {
        handle_retrieve(connfd, body, request.length);
    } else if (request.command == COMMAND_INFORM) {
        /*
        INFORM contains exactly one peer adress: (16 bytes IP) + (4 port) + (32 signature) + (16 salt).
        */
        if (request.length != PEER_ADDR_LEN) {
            fprintf(stderr, "Invalid inform body length. \n");
        } else {
            //Extract the peer being announced
            char new_ip[IP_LEN + 1];

            memcpy(new_ip, body, IP_LEN);
            new_ip[IP_LEN] = '\0';

            uint32_t network_port;
            memcpy(&network_port, body + IP_LEN, PORT_LEN);
            network_port = ntohl(network_port);

            hashdata_t network_signature;
            memcpy(network_signature, body + IP_LEN + PORT_LEN, SHA256_HASH_SIZE);

            char network_salt[SALT_LEN];
            memcpy(network_salt, body + IP_LEN + PORT_LEN +SHA256_HASH_SIZE, SALT_LEN);

            // VAlidate the new peer adress
            if (strnlen(new_ip, IP_LEN) == IP_LEN || !is_valid_ip(new_ip) || !is_valid_port(network_port) || network_port ==0) {

                fprintf(stderr, "Invalid peer in INFORM \n");
            } else {
                // Protect the shared network whhile updating it.
                pthread_mutex_lock(&network_mutex);

                if (find_peer(new_ip, network_port) == NULL) {
                    add_peer(new_ip, network_port, network_signature, network_salt);

                    printf("Added new peer: %s:%u \n", new_ip, network_port);
                    printf("Network now contains %u peers! \n", peer_count);
                } else {
                    printf("INFORM: peer %s:%u already in network! \n", new_ip, network_port);
                }

                pthread_mutex_unlock(&network_mutex);
            }
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