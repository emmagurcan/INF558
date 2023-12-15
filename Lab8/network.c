/**************************************************************************/
/*                                                                        */
/* network                                                                */
/*                                                                        */
/* Allows to send and receive text messages over TCP sockets. Each        */
/* message is sent in a separate TCP session, no state is maintained      */
/* between connections. Both sending and receiving are blocking, but      */
/* receiving allows for a timeout.                                        */
/*                                                                        */
/* Original author: Andreas Enge, 17.03.2006                              */
/* Modified: FMorain, 2017                                                */
/* Modified: Maxime Bombar <maxime.bombar@inria.fr>, 2022-11-21           */
/*           (Support IPV6 and remove compilation warnings)               */
/*                                                                        */
/**************************************************************************/


#define NG_MAXCONNECTIONS 5
#define DEFAULT_PORT 31415 // Pi is unassigned by IANA. See https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.xhtml?&page=130
#define NO_DEBUG
#define _POSIX_C_SOURCE 200809L // Enable POSIX.1-2008 extension

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <math.h>
#include <unistd.h>
#include <netdb.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define DEBUG 0

/* to be filled in */

static int sock;
   /* socket for listening to incoming connections */


/**************************************************************************/
/*                                                                        */
/* helper functions                                                       */
/*                                                                        */
/**************************************************************************/

static void myerror (const char * message)
{
#ifdef CORRECTION
   fprintf(stderr, "%s: %s\n", message, strerror(errno));
#else
   perror(message);
   exit(1);
#endif
}
      
/**************************************************************************/

static void myherror (const char * message, int herrno)
{
   fprintf(stderr, "%s: %s\n", message, gai_strerror(herrno));
#ifndef CORRECTION
   exit(1);
#endif
}

/**************************************************************************/

static void myrcverror (const char * message, int code)
{
   if (code == -1)
      myerror (message);
   else if (code == 0)
   {
      printf ("Peer closed connection: %s", message);
      exit (1);
   }
}
      
/**************************************************************************/

static int send_bytes (int sock, const char * mesg, int bytes)
   /* sends out the given number of bytes from mesg; returns the number
      of bytes upon success, and -1 upon error */
{
   const char * buffer = mesg;
   int total = bytes, tmp;
   
   while (bytes > 0)
   {
      tmp = send (sock, buffer, bytes, 0);
      if (tmp == -1)
         return -1;
      bytes -= tmp;
      buffer += tmp;
   }
      
   return total;
}

/**************************************************************************/

static int recv_bytes (int sock, char * mesg, int bytes)
   /* receives the given number of bytes in mesg; returns the number
      of bytes upon success, -1 upon error and 0 upon closed connection;
      mesg must already be initialised */
{
   char * buffer = mesg;
   int total = bytes, tmp;
   
   while (bytes > 0)
   {
      tmp = recv (sock, buffer, bytes, 0);
      if (tmp <= 0)
         return -1;
      bytes -= tmp;
      buffer += tmp;
   }
      
   return total;
}

/**************************************************************************/

static int send_message (int sock, const char * mesg)
   /* sends out the message without the '\0' termination prepended by four
      bytes in network byte order giving its length; returns the length of
      the message upon success, and -1 upon error */
{
   unsigned long int length;
   
   length = htonl (strlen (mesg));
      /* the 0 termination is not sent */
   if (send_bytes (sock, (char *) &length, 4) == -1)
      myerror ("send_message send_bytes");
   
   return send_bytes (sock, mesg, ntohl (length));
}

/**************************************************************************/

static int recv_message (int sock, char ** mesg)
   /* receives a message that was prepended by its length; allocates the
      necessary memory and adds a '\0' termination; returns the length
      of the message upon success, -1 upon error and 0 upon closed
      connection */
{
   unsigned long int length;
   int error;
   
   length = 0;
   error = recv_bytes (sock, (char *) &length, 4);
   if (error <= 0)
      myrcverror ("recv_message recv_bytes", error);
   length = ntohl (length);
   
   *mesg = (char *) malloc (length + 1);
   (*mesg) [length] = '\0';
   
   return recv_bytes (sock, *mesg, length);
}

/**************************************************************************/
/*                                                                        */
/* exported functions                                                     */
/*                                                                        */
/**************************************************************************/

int check_port(int nport) {
   /* Usage: Check if port is already used */
   if (nport < 1024 || nport > 65535) {
      return 0;
   }
   int tmp_sock = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
   struct sockaddr_in6 tmp_server_addr;
   tmp_server_addr.sin6_family = AF_INET6;
   tmp_server_addr.sin6_addr = in6addr_any;
   tmp_server_addr.sin6_port = htons(nport);
   tmp_server_addr.sin6_flowinfo = 0;
   tmp_server_addr.sin6_scope_id = 0;
   
   int ret = bind(tmp_sock, (struct sockaddr*)&tmp_server_addr, sizeof(tmp_server_addr));
   close(tmp_sock);

   if (ret == -1){
      return 0;
   }
   else {
      return 1;
   }
}


void network_init (int nport)
   /* starts to listen for connections; is only needed when receiving
      messages, not for sending
      ATTENTION: Cannot be called by two processes on the same machine,
      since a fixed port is blocked. */

{
   struct sockaddr_in6 server_addr;

   sock = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
   if (sock == -1) {
      myerror("socket()");
   }

   int flag = 1;
   int ret = setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &flag, sizeof(int));

   if (ret == -1) {
      myerror("setsockopt()");
   }

   server_addr.sin6_family = AF_INET6;
   server_addr.sin6_addr = in6addr_any;
   server_addr.sin6_port = htons(nport);
   server_addr.sin6_flowinfo = 0;
   server_addr.sin6_scope_id = 0;

   ret = bind(sock, (struct sockaddr*)&server_addr, sizeof(server_addr));

   if (ret == -1) {
      myerror("bind()");
   }


   if (listen (sock, NG_MAXCONNECTIONS) == -1)
      myerror ("network_init listen");
}

/**************************************************************************/

void network_clear ()
   /* cleans up, must be called after network_init */

{
   close (sock);
}

/**************************************************************************/

void build_packet(char *packet, const char* client, const int cport, const char *mesg) {
   // Build the packet <client>:<cport>:<mesg>
   const char *delim = ";";
   sprintf(packet, "%s%s%d%s%zu%s%s", client, delim, cport, delim, strlen(mesg), delim, mesg);
}

int parse_packet(char **client, int *cport, char **msg, const char *packet) {
   /* Parse a packet as <client>;<cport>;<len>;<msg> */

   if (packet == NULL) {
       fprintf(stderr, "recv NULL packet\n");
       return 0;
   }

   char cppacket[strlen(packet)];

   strcpy(cppacket, packet);

   char *ptr;
   char delim[] = ";";

   ptr = strtok(cppacket, delim);

   if (client != NULL) {
      *client = malloc(sizeof(char)*(strlen(ptr)+1));
      if (*client == NULL) {
         return 0;
      }
      sprintf(*client, "%s", ptr);
   }

   ptr = strtok(NULL, delim);
   if (cport != NULL) {
      *cport = atoi(ptr);
      if (*cport == 0) {
	  fprintf(stderr, "Recv 0 cport\n");
         return 0;
      }
   }

   ptr = strtok(NULL, delim);
   if (msg != NULL) {
      *msg = malloc(sizeof(char)*atoi(ptr)+1);
      if (*msg == NULL) {
         return 0;
      }

      ptr = strtok(NULL, delim);
      sprintf(*msg, "%s", ptr);

      ptr = strtok(NULL, delim);
      while (ptr != NULL) {
         strcat(*msg, ";");
         strcat(*msg, ptr);
         ptr = strtok(NULL, delim);
      }
   }
   free(ptr); // ptr should be NULL but we never know....
   return 1;
}

void network_send (const char *host, const int port, const char *client, const int cport, const char *mesg)
/* void network_send (const char * host, const int port, const char * mesg) */
/* sends the given message to the host of the given name */
   /* host = name or ip address of host
    * port = port on which server listen on host
    * client = name or ip address of client. Can be localhost
    * cport = port on which client listens (if needed)
    * Packet format is <client>;<cport>;<len(msg)>;mesg */
      
{
   /* const char* client = (char*)"localhost"; */
   /* const int cport = 1789; */
   int sendsock, bytes_sent, yes;
   int length = (int)(ceil((log10(strlen(mesg))))+1);
   int size = strlen(client) + 3 + 5 + 3 + length + 3 + strlen(mesg) + 1; // Last +1 is for ending NULL
   char packet[size];

   build_packet(packet, client, cport, mesg);

#if DEBUG >= 1
   printf("Will send packet %s\n", packet);
#endif

   char service[6];
   struct addrinfo hints;
   struct addrinfo *result;
   int herrno;

   memset(&hints, 0, sizeof(struct addrinfo));
   hints.ai_socktype = SOCK_STREAM;
   hints.ai_family = AF_UNSPEC;
   hints.ai_flags = AI_CANONNAME;

   sprintf(service, "%d", port);

   herrno = getaddrinfo(host, service, &hints, &result);

   if (herrno != 0) { // don't freeaddrinfo(result), NULL pointer
      myherror("network_send getaddrinfo", herrno);
      return;
   }

   sendsock = socket(result->ai_family, result->ai_socktype, IPPROTO_TCP);
   if (sendsock == -1){
      freeaddrinfo(result);
      myerror ("network_send socket");
      return;
   }


   yes = 1;
   if (setsockopt (sendsock, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof (int))
       == -1){
      freeaddrinfo(result);
      myerror ("network_send setsockopt");
      return;
   }

   if (connect (sendsock, result->ai_addr, result->ai_addrlen) != 0){
#ifdef CORRECTION
      fprintf(stderr, "Trying to connect to %s:%s\n", host, service);
#endif
      freeaddrinfo(result);
      myerror ("network_send connect");
      return;
   }
#if DEBUG >= 1
   char buf[1000];
   struct sockaddr_in6 *sin = (struct sockaddr_in6 *)result->ai_addr;
   printf("Connection to %s:\n", inet_ntop(result->ai_family, &sin->sin6_addr, buf, sizeof(buf)));
   free(buf);
#endif

   bytes_sent = send_message (sendsock, packet);
   if (bytes_sent == -1)
      myerror ("network_send send_bytes");
   freeaddrinfo(result);
   close(sendsock);
}

/**************************************************************************/

char * network_recv (int timeout)
   /* waits up to timeout seconds for a message and returns it;
      if no message has arrived, returns NULL. If timeout is
      negative, waits indefinitely for a message */

{
   char * mesg;
   int recsock, bytes_received, err;
   fd_set set;
   struct timeval waiting;
   unsigned int sendersize;
   struct sockaddr_in6 sender;
   
   FD_ZERO (&set);
   FD_SET (sock, &set);
   if (timeout >= 0)
   {
      waiting.tv_sec = timeout;
      waiting.tv_usec = 0;
      err = select (sock + 1, &set, NULL, NULL, &waiting);
   }
   else
      err = select (sock + 1, &set, NULL, NULL, NULL);
   if (err == -1)
      myerror ("network_receive select");
   if (!FD_ISSET (sock, &set))
      return NULL;
   
   sendersize = sizeof(sender);
   recsock = accept (sock, (struct sockaddr *) &sender, &sendersize);
   if (recsock == -1)
      myerror ("network_receive accept");
/* #ifdef DEBUG */
/*       printf ("Incoming connection from %s:%hi\n", */
/*             inet_ntoa (sender.sin_addr), sender.sin_port); */
/* #endif */

   bytes_received = recv_message (recsock, &mesg);
   if (bytes_received <= 0)
      myrcverror ("network_receive recv_bytes", bytes_received);
   
   close (recsock);
   
   return (mesg);
}

/**************************************************************************/
