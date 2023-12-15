#ifndef __FRS__NETWORK

/**************************************************************************/
/*                                                                        */
/* network                                                                */
/*                                                                        */
/* Allows to send and receive text messages over TCP sockets. Each        */
/* message is sent in a separate TCP session, no state is maintained      */
/* between connections. Both sending and receiving are blocking, but      */
/* receiving allows for a timeout.                                        */
/*                                                                        */
/* Andreas Enge                                                           */
/*                                                                        */
/* 17.03.2006                                                             */
/*                                                                        */
/* modified by Maxime Bombar <maxime.bombar@inria.fr>                     */
/* 25.11.2022                                                             */
/**************************************************************************/

void network_init (int nport);
   /* starts to listen for connections; is only needed when receiving
      messages, not for sending
      ATTENTION: Cannot be called by two processes on the same machine,
      since a fixed port is blocked. */
void network_clear ();
   /* cleans up, must be called after network_init */

void network_send (const char *host, const int port, const char *client, const int cport, const char *mesg);
   /* sends the given message to the host of the given name */
char * network_recv (int timeout);
   /* waits up to timeout seconds for a message and returns it;
      if no message has arrived, returns NULL. If timeout is
      negative, waits indefinitely for a message */

void build_packet(char *packet, const char* client, const int cport, const char *mesg);
int parse_packet(char **client, int *cport, char **msg, const char *packet);
int check_port(int nport);

#define __FRS__NETWORK
#endif
