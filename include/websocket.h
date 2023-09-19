#ifndef _WEBSOCKET_H_
#define _WEBSOCKET_H_

#include <mbedtls/ssl.h>
#include <mbedtls/x509_crt.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>

#include <unitypes.h>
#include <string>
#include <list>

class Websocket
{
public:
    enum OpCode
    {
        CONTINUE,
        TEXT,
        BINARY,
        CLOSE = 8,
        PING,
        PONG,
        FIN = 0x80
    };

    struct Frame
    {
        uint fin;
        uint opcode;
        uint mask_off;

        uint headerSize;
        
        // Size of actual *Websocket* payload that has been sent
        unsigned long long payload_len;

        std::string rawdata;
        u_char mask[4];

        Frame()
        {
            headerSize = 2;
            payload_len = -1;
        }
    };

    Websocket(std::string uri);
    ~Websocket();

    // Connect to the host and initiate the Websocket handshake
    void Connect();

    // Start the Process Thread and begin handling data input / output
    void StartProcessing();

    // Wait until the Process Thread ends
    void WaitEnd();

    // Close the connection and exit the Process Thread
    void Disconnect();
    
    // Send message to the websocket
    int SendMessage(std::string data, unsigned char opcode = FIN | TEXT);
    
    // Send message with no payload
    int SendControlFrame(unsigned char opcode);

    bool IsConnected()
    {
        return sockfd > 0;
    }

    virtual void OnOpen() = 0;
    virtual void OnClose() = 0;
    virtual void OnError(int code, std::string error) = 0;
    virtual void OnMessage(std::string& message, unsigned char opcode) = 0;

private:

    static const char *UpgradeHeaders;

    enum Flags
    {
        WS_FLAGS_SSL_INIT = (1 << 0),
        CLIENT_IS_SSL = (1 << 0),
        CLIENT_CONNECTING = (1 << 1),
        CLIENT_SHOULD_CLOSE = (1 << 2),
        CLIENT_SENT_CLOSE_FRAME = (1 << 3),
        REQUEST_HAS_CONNECTION = (1 << 4),
        REQUEST_HAS_UPGRADE = (1 << 5),
        REQUEST_VALID_STATUS = (1 << 6),
        REQUEST_VALID_ACCEPT = (1 << 7),
    };

    static void *HandshakeThread(void *arg);
    static void *ProcessThread(void *arg);

    int OpenConnection();
    int CloseConnection();

    void DispatchMessage();

    void HandleControlFrame(Frame &frame);
    
    int Write(const void *buff, size_t size);
    int Read(void *buff, size_t size);

    int DataIn(char *buff, size_t size);

    void CleanupFrames()
    {
        pthread_mutex_lock(&lock);
        frames.clear();
        pthread_mutex_unlock(&lock);
    }

    bool ShouldClose()
    {
        return (flags & CLIENT_SHOULD_CLOSE) == CLIENT_SHOULD_CLOSE;
    }

    // Some globals we'll need initialising mbedtls for SSL
    static mbedtls_entropy_context g_entropy;
    static mbedtls_ctr_drbg_context g_ctr_drbg;
    static mbedtls_ssl_config g_ssl_conf;
    static mbedtls_x509_crt g_cacert;

    static int g_flags;

    pthread_t handshakeThread;
    pthread_t processThread;
    
    pthread_mutex_t lock;
    pthread_mutex_t write_lock;
    
    std::string URI;
    
    std::string host;
    std::string file;
    std::string service;

    int sockfd;
    int flags;

    // SSL
    mbedtls_ssl_context ssl;

    std::list<Frame> frames;
};

#endif