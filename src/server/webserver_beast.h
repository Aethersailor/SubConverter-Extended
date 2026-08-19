#ifndef WEBSERVER_BEAST_H_INCLUDED
#define WEBSERVER_BEAST_H_INCLUDED

struct listener_args;
class WebServer;

int startBeastWebServer(WebServer &server, listener_args *args);

#endif // WEBSERVER_BEAST_H_INCLUDED
