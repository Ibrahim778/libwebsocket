# libwebsocket

My own websocket client library written in C++

- Aims to be simple, doesn't require any dependecies apart from C++11 and mbedtls (if you're using SSL)  
- Example usage in src/example.cpp

Required code for the library are in the following files (inside src/):
    - base64.c
    - sha1.c
    - websocket.cpp

Include files needed for the libary are the following (inside include/):
    - certs.h
    - websocket.h

Note: This library currently contains test SSL certificates taken from the MbedTLS example code

The following references were used in the making of this library:
    - [libwsclient](https://github.com/payden/libwsclient)
    - [Websocket Framing by some legend](https://www.openmymind.net/WebSocket-Framing-Masking-Fragmentation-and-More/#:~:text=A%20WebSocket%20frame%20can%20be,not%20it's%20a%20fin%20frame.)
    - [Websocket Standard](https://datatracker.ietf.org/doc/html/rfc6455)
