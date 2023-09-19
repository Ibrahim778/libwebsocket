#include <stdio.h>
#include <string>
#include <list>
#include <unistd.h>
#include <sys/socket.h>

#include <mbedtls/ssl.h>
#include <mbedtls/x509_crt.h>
#include <mbedtls/entropy.h>
#include <mbedtls/net_sockets.h>
#include <mbedtls/ctr_drbg.h>

#include <pthread.h>

#include "websocket.h"
#include "certs.h"
#include "sha1.h"

extern "C"
{
    int base64_encode(char *source, size_t sourcelen, char *target, size_t targetlen);
};

mbedtls_entropy_context Websocket::g_entropy;
mbedtls_ctr_drbg_context Websocket::g_ctr_drbg;
mbedtls_ssl_config Websocket::g_ssl_conf;
mbedtls_x509_crt Websocket::g_cacert;

int Websocket::g_flags = 0;

const char *Websocket::UpgradeHeaders = "GET %s HTTP/1.1\r\n"
                                        "Host: %s:%s\r\n"
                                        "Connection: Upgrade\r\n"
                                        "Upgrade: websocket\r\n"
                                        "Sec-WebSocket-Key: %s\r\n"
                                        "Sec-WebSocket-Version: 13\r\n"
                                        "\r\n";

Websocket::Websocket(std::string uri)
{
    memset(&ssl, 0, sizeof(ssl));
    flags = 0;
    sockfd = 0;

    if (pthread_mutex_init(&lock, nullptr) != 0)
    {
        printf("[Abort] Unable to init \'lock\' mutex in Websocket::Websocket\n");
        abort();
        return; // is this even needed?
    }

    if (pthread_mutex_init(&write_lock, nullptr) != 0)
    {
        printf("[Abort] Unable to init \'write_lock\' mutex in Websocket::Websocket\n");
        abort();
        return; // is this even needed?
    }

    pthread_mutex_lock(&lock);

    auto protocolStart = uri.find("://");
    if (protocolStart == std::string::npos)
    {
        printf("[Abort] Invalid / malformed scheme for URI (%s)\n", uri.c_str());
        abort();
        return;
    }

    // Check protocol and assign SSL flags and default port numbers
    if (uri.rfind("wss", 0) != std::string::npos) // Websocket Secusre connection (With SSL)
    {
        printf("[Websocket] Secure Websocket Connection\n");
        service = "443";
        flags |= CLIENT_IS_SSL;
    }
    else if (uri.rfind("ws", 0) != std::string::npos)
    {
        printf("[Websocket] Standard Websocket Connection\n");
        service = "80";
    }
    else
    {
        printf("[Abort] Invalid protocol for URI (%s)\n", uri.c_str());
        abort();
        return;
    }

    // Check and assign specific port number if in URI
    auto serviceStart = uri.find(":", protocolStart + 4);
    if (serviceStart != std::string::npos)
        service = uri.substr(serviceStart + 1, uri.length() - serviceStart);

    printf("[Websocket] Port: %s\n", service.c_str());

    file = "/"; // Set a default file path incase none is specified

    auto fileStart = uri.find("/", protocolStart + 4);
    if (fileStart != std::string::npos)
        file = uri.substr(fileStart, (serviceStart != std::string::npos ? serviceStart : uri.length()) - fileStart);

    printf("[Websocket] File: %s\n", file.c_str());

    host = uri.substr(protocolStart + 3, fileStart == std::string::npos ? serviceStart - (protocolStart + 3) : fileStart - (protocolStart + 3));
    printf("[Websocket] Host: %s\n", host.c_str());

    pthread_mutex_unlock(&lock);
}

Websocket::~Websocket()
{
    if (handshakeThread)
    {
        pthread_join(handshakeThread, nullptr);
    }

    if (IsConnected())
    {
        Disconnect();
        WaitEnd();
    }

    pthread_mutex_destroy(&lock);
    pthread_mutex_destroy(&write_lock);
}

void Websocket::Connect()
{
    pthread_mutex_lock(&lock);
    flags |= CLIENT_CONNECTING;
    pthread_mutex_unlock(&lock);

    pthread_create(&handshakeThread, nullptr, HandshakeThread, this);
    pthread_join(handshakeThread, nullptr);

    handshakeThread = nullptr;
}

int Websocket::OpenConnection()
{
    int res = 0;
    if (flags & CLIENT_IS_SSL)
    {
        if ((g_flags & CLIENT_IS_SSL) == 0)
        {
            mbedtls_ssl_config_init(&g_ssl_conf);
            mbedtls_x509_crt_init(&g_cacert);
            mbedtls_ctr_drbg_init(&g_ctr_drbg);

            mbedtls_entropy_init(&g_entropy);

            printf("[Websocket] mbedtls_ctr_drbg_seed\n");

            res = mbedtls_ctr_drbg_seed(&g_ctr_drbg, mbedtls_entropy_func, &g_entropy, (const unsigned char *)"libwebsocketclient", 18);

            if (res != 0)
            {
                printf("[Websocket] failed! mbedtls_ctr_drbg_seed returned %d\n", res);
                return res;
            }

            printf("[Websocket] Loading the CA root certificate\n");

            res = mbedtls_x509_crt_parse(&g_cacert, (const unsigned char *)mbedtls_test_cas_pem, mbedtls_test_cas_pem_len);

            if (res != 0)
            {
                printf("failed! mbedtls_x509_crt_parse returned -0x%x\n", (unsigned int)-res);
                return res;
            }

            printf("[Websocket] ok (%d skipped)\n", res);

            printf("[Websocket] Setting up the SSL/TLS config structure\n");

            res = mbedtls_ssl_config_defaults(&g_ssl_conf,
                                              MBEDTLS_SSL_IS_CLIENT,
                                              MBEDTLS_SSL_TRANSPORT_STREAM,
                                              MBEDTLS_SSL_PRESET_DEFAULT);
            if (res != 0)
            {
                printf("[Websocket] failed! mbedtls_ssl_config_defaults returned %d\n", res);
                return res;
            }

            mbedtls_ssl_conf_authmode(&g_ssl_conf, MBEDTLS_SSL_VERIFY_OPTIONAL);
            mbedtls_ssl_conf_ca_chain(&g_ssl_conf, &g_cacert, NULL);
            mbedtls_ssl_conf_rng(&g_ssl_conf, mbedtls_ctr_drbg_random, &g_ctr_drbg);
            // mbedtls_ssl_conf_dbg(&ssl_conf, my_debug, nullptr);

            g_flags |= WS_FLAGS_SSL_INIT;

            printf("[Websocket] Global SSL Setup completed!\n");
        }

        // Now we init OUR client specific things

        res = mbedtls_ssl_setup(&ssl, &g_ssl_conf);
        if (res != 0)
        {
            printf("[Websocket] failed! mbedtls_ssl_setup returned %d\n", res);
            return res;
        }

        printf("[Websocket] SSL setup\n");

        res = mbedtls_ssl_set_hostname(&ssl, host.c_str());
        if (res != 0)
        {
            printf("[Websocket] failed! mbedtls_ssl_set_hostname returned %d\n\n", res);
            return res;
        }

        printf("[Websocket] SSL hostname set\n");

        mbedtls_ssl_set_bio(&ssl, &sockfd, mbedtls_net_send, mbedtls_net_recv, NULL);

        printf("[Websocket] SSL bio set\n");

        mbedtls_net_init((mbedtls_net_context *)&sockfd);

        printf("[Websocket] Net ready\n");

        res = mbedtls_net_connect((mbedtls_net_context *)&sockfd, host.c_str(), service.c_str(), MBEDTLS_NET_PROTO_TCP);
        if (res != 0)
        {
            mbedtls_ssl_free(&ssl);
            mbedtls_net_free((mbedtls_net_context *)&sockfd);
            return res;
        }

        // Now we perform the SSL handshake
        printf("[Websocket] Performing the SSL/TLS handshake\n");

        while ((res = mbedtls_ssl_handshake(&ssl)) != 0)
        {
            if (res != MBEDTLS_ERR_SSL_WANT_READ && res != MBEDTLS_ERR_SSL_WANT_WRITE)
            {
                printf("[Websocket] failed 0x%X\n", (unsigned int)-res);
                return res;
            }
        }

        printf("[Websocket] ok\n");

        return 0;
    }
    else
    {
        // TODO: implement (lol)
    }

    return -1;
}

void Websocket::Disconnect()
{
    SendControlFrame(CLOSE);

    pthread_mutex_lock(&lock);
    flags |= CLIENT_SENT_CLOSE_FRAME | CLIENT_SHOULD_CLOSE;
    pthread_mutex_unlock(&lock);
}

int Websocket::CloseConnection()
{
    if (flags & CLIENT_IS_SSL)
    {
        mbedtls_ssl_close_notify(&ssl);
        mbedtls_ssl_free(&ssl);
        mbedtls_net_free((mbedtls_net_context *)&sockfd);
    }
    else
        close(sockfd);
    return 0;
}

void Websocket::StartProcessing()
{
    if (flags & CLIENT_CONNECTING && handshakeThread)
    {
        pthread_join(handshakeThread, NULL);
    }

    if (flags & CLIENT_CONNECTING || !IsConnected()) // Connection failed :(
    {
        OnError(0, "Cannot start processing, the client failed to connect");
        return;
    }

    pthread_create(&processThread, nullptr, ProcessThread, this); // Now we start the process thread
}

void Websocket::WaitEnd()
{
    if (handshakeThread)
    {
        pthread_join(handshakeThread, nullptr);
    }

    if (processThread)
    {
        pthread_join(processThread, nullptr);
        processThread = nullptr;
    }
}

int Websocket::DataIn(char *data, size_t len)
{
    int used = 0;

    // Create new frame in our list if we dont have one currently
    if (frames.size() == 0)
        frames.push_back(Frame());

    auto &frame = frames.back();
    auto pPayload = (char *)frame.rawdata.data();

    auto payload_len_short = 0;

    pthread_mutex_lock(&lock);

    // First we ensure our header is complete
    if (frame.rawdata.size() < frame.headerSize)
    {
        used = frame.headerSize - frame.rawdata.size();
        frame.rawdata += std::string(data, used);
        pthread_mutex_unlock(&lock);
        return used;
    }
    else if (frame.payload_len == -1) // Now parse our header if we haven't already
    {
        // Read the first byte and assign header data
        frame.fin = (pPayload[0] & 0x80) == 0x80 ? 1 : 0;
        frame.opcode = (pPayload[0] & 0x0F);

        // check mask bit, MUST be 0
        if ((pPayload[1] & 0x80) != 0)
        {
            OnError(0, "Server sent a masked frame");
            flags |= CLIENT_SHOULD_CLOSE;
            pthread_mutex_unlock(&lock);
            return 0;
        }

        payload_len_short = pPayload[1] & 0x7f;
        switch (payload_len_short)
        {
        case 126: // Extra 2 byte length
            frame.headerSize = 4;
            if (frame.rawdata.size() < 4)
            {
                pthread_mutex_unlock(&lock);
                return 0;
            }

            frame.payload_len = ntohs(*(uint16_t *)(pPayload + 2));
            break;

        case 127:
            frame.headerSize = 10;
            if (frame.rawdata.size() < 10)
            {
                pthread_mutex_unlock(&lock);
                return 0;
            }

            frame.payload_len = ntohll(*(uint64_t *)(pPayload + 2));
            break;

        default:
            frame.payload_len = payload_len_short;
            break;
        }

        pthread_mutex_unlock(&lock);
        return 0; // Now we return, actual payload data will be collected starting from the next call
    }

    auto remaining_size = (frame.payload_len + frame.headerSize) - frame.rawdata.size();
    used = remaining_size > len ? len : remaining_size;
    frame.rawdata += std::string(data, used); // NOW we append the actual payload data

    pthread_mutex_unlock(&lock);

    // Now check if the frame has been completed, if so handle it
    if (frame.rawdata.size() == frame.payload_len + frame.headerSize)
    {
        if (frame.fin == 1) // Frame is a finish frame
        {

            if ((frame.opcode & 0x08) == 0x08) // Is control frame
            {
                HandleControlFrame(frame);
                pthread_mutex_lock(&lock);
                frames.pop_back(); // Control frames can't be fragmented and so dont need to be saved
                pthread_mutex_unlock(&lock);
            }
            else
                DispatchMessage();
        }

        pthread_mutex_lock(&lock);
        frames.push_back(Frame());
        pthread_mutex_unlock(&lock);
    }

    return used;
}

void Websocket::DispatchMessage()
{
    if(frames.size() == 0)
    {
        OnError(0, "Trying to dispatch a message when there are no saved frames!");
        return;
    }

    auto frame = frames.begin();

    std::string message;
    auto opcode = frame->opcode;

    while(frame != frames.end())
    {
        message += std::string(frame->rawdata.data() + frame->headerSize, frame->payload_len);
        frame++;
    }

    CleanupFrames();

    OnMessage(message, opcode);
}

int Websocket::SendControlFrame(unsigned char opcode)
{
    char frame[2];
    frame[0] = opcode | FIN;
    frame[1] = 0;

    int sent = 0;
    int n = 0;

    pthread_mutex_lock(&write_lock);

    do
    {
        n = Write(frame + sent, 2 - sent);
        sent += n;
    } 
    while(n > 0 && sent < n);

    pthread_mutex_unlock(&write_lock);

    if(n < 0)
    {
        OnError(n, "Failed to send control frame");
        return n;
    }

    return sent;
}

int Websocket::SendMessage(std::string data, unsigned char fin_opcode)
{
    char mask[4];
    uint64_t frameSize;
    uint lenSmall; // size to apply to second bye
    uint headerSize = 6;

    srand(time(nullptr));
    int maskInt = rand();
    memcpy(mask, &maskInt, 4);

    if (flags & CLIENT_SENT_CLOSE_FRAME)
    {
        OnError(0, "Client tried to send data after sending close frame");
        return 0;
    }

    if (flags & CLIENT_CONNECTING)
    {
        OnError(0, "Client tried to send data before / during connection");
        return 0;
    }

    uint64_t len = data.size();

    if (len == 0)
        printf("[Websocket] WARN trying to send message with size 0!\n");
    
    if(len <= 125)
    {
        frameSize = len + headerSize;
        lenSmall = len;
    }
    else if(len > 125 && len <= 0xFFFF)
    {
        headerSize += 2;
        frameSize = 8 + headerSize;
        lenSmall = 126;
    }
    else if(len > 0xFFFF && len < 0xFFFFFFFFFFFFFFFFLL)
    {
        headerSize += 8;
        frameSize = len + headerSize;
        lenSmall = 127;
    }
    else 
    {
        OnError(0, "Send data too large! just WHAT are you trying to send??");
        return -1; 
    }

    auto frame = new char[frameSize];

    memset(frame, 0, frameSize);

    frame[0] = fin_opcode;
    *(frame + 1) = lenSmall | 0x80; // Length with the MASK bit on

    if(lenSmall == 126)
    {
        len &= 0xFFFF; // Ensure it's within range
        *(uint16_t *)&frame[2] = htons(len);
    }
    else if(lenSmall == 127)
    {
        len &= 0xFFFFFFFFFFFFFFFFLL;
        *(uint64_t *)&frame[2] = htonll(len);
    }

    *(int *)&frame[headerSize - 4] = maskInt; // assign mask integer at the end of the header
    
    memcpy(frame + headerSize, data.data(), data.length()); // copy over the data
    for(int i = 0; i < data.length(); i++)
        frame[headerSize + i] ^= mask[i % 4] & 0xFF;
    
    int sent = 0;
    int res = 0;

    pthread_mutex_lock(&lock);

    do
    {
        res = Write(frame + sent, frameSize - sent);
        sent += res;
    } while (res > 0 && sent < frameSize);

    pthread_mutex_unlock(&lock);

    delete[] frame;

    if(res < 0)
    {
        OnError(res, "Failed to send data");
        return res;
    }

    return sent;
}

void Websocket::HandleControlFrame(Frame &frame)
{
    int mask; // Mask value that we will use for... masking the payload (Required by Websocket Standard .-.)
    int res;

    srand(time(nullptr));

    mask = rand();

    pthread_mutex_lock(&lock); // Don't really think we need this but i guess?
    switch (frame.opcode)
    {
    case CLOSE:
        printf("[Websocket] Server has sent a close frame\n");
        if ((flags & CLIENT_SENT_CLOSE_FRAME) == 0)
        {
            // Send a close frame as acknowledgement
            
            int n = SendControlFrame(CLOSE);

            flags |= CLIENT_SENT_CLOSE_FRAME | CLIENT_SHOULD_CLOSE;

            if (n < 0)
            {
                OnError(n, "Error while sending close frame");
            }
        }
        break;

    case PING:
        printf("[Websocket] Server has sent a ping frame\n");
        res = SendControlFrame(PONG);
        if (res <= 0)
        {
            OnError(res, "Client failed to send control (PONG) frame");
            break;
        }
        printf("[Websocket] Client has sent a pong frame\n");
        break;
    case PONG:
        printf("[Websocket] Server has sent a PONG frame\n");
        break;
    default:
        printf("[Websocket] WARN unknown control frame received: 0x%X, unhandled\n", frame.opcode);
        break;
    }

    pthread_mutex_unlock(&lock);
}

void *Websocket::ProcessThread(void *userDat)
{
    auto client = (Websocket *)userDat;

    printf("[Start] Process Thread\n");

    char buff[0x400];

    int n = 0;
    while (!client->ShouldClose())
    {
        n = client->Read(buff, sizeof(buff) - 1);
        if(n < 0)
            break;

        int processed = 0;
        int z = 0;
        do
        {
            z = client->DataIn(buff + processed, n - processed);
            processed += z;
        } while (z >= 0 && processed < n && !client->ShouldClose());
    }

    if (n < 0)
        client->OnError(n, "Error while receiving data");

    client->OnClose();

    client->CloseConnection();

    client->CleanupFrames();

    printf("[Stop] Process Thread\n");

    return nullptr;
}

void *Websocket::HandshakeThread(void *userDat)
{
    printf("[Start] Handshake Thread\n");

    char headers[0x400];
    char key[16];        // Encryption key
    char key64[256];     // Encryption key in base-64
    char respKey[20];    // Servers accept key
    char respKey64[256]; // Servers accept key in base-64
    SHA1Context shactx;
    auto n = 0, received = 0;
    auto client = (Websocket *)userDat;

    auto connectionRes = client->OpenConnection();
    if (connectionRes < 0)
    {
        client->OnError(connectionRes, "Failed to open connection");
        return nullptr;
    }

    srand(time(nullptr)); // Seed the random number generator
    for (int i = 0; i < 16; i++)
        key[i] = rand() & 0xFF;

    base64_encode(key, sizeof(key), key64, sizeof(key64));

    snprintf(headers, sizeof(headers), UpgradeHeaders, client->file.c_str(), client->host.c_str(), client->service.c_str(), key64);

    printf("[Websocket] Connection headers are as follows:\n%s\n", headers);

    n = client->Write(headers, strnlen(headers, sizeof(headers)));

    printf("[Websocket] Connection headers have been sent\n");

    received = 0;
    do
    {
        n = client->Read(headers + received, sizeof(headers) - received - 1);
        received += n;
    } while ((strstr(headers, "\r\n\r\n") == nullptr || received < 4) && n > 0);

    if (received == 0)
    {
        client->OnError(0, "Connection closed by host");
        return nullptr;
    }

    if (n < 0)
    {
        client->OnError(n, "Error while receiving handshake");
        return nullptr;
    }

    printf("[Websocket] Response headers are as follows:\n%s\n", headers);

    // Calculate the expected Sec-WebSocket-Accept key
    snprintf(respKey64, sizeof(respKey64), "%s%s", key64, "258EAFA5-E914-47DA-95CA-C5AB0DC85B11");

    SHA1Reset(&shactx);
    SHA1Input(&shactx, (unsigned char *)respKey64, strlen(respKey64));
    SHA1Result(&shactx);

    memset(respKey, 0, sizeof(respKey));

    for (int i = 0; i < 5; i++)
        shactx.Message_Digest[i] = htonl(shactx.Message_Digest[i]); // Ensure we're in the right byte order (big endian)

    base64_encode((char *)shactx.Message_Digest, 20, respKey64, sizeof(respKey64));

    printf("[Websocket] Expected response key: %s\n", respKey64);

    // Now we parse the result we got to ensure the response headers are valid

    for (auto tok = strtok(headers, "\r\n"); tok != NULL; tok = strtok(NULL, "\r\n"))
    {
        char *p;
        if (*tok == 'H' && *(tok + 1) == 'T' && *(tok + 2) == 'T' && *(tok + 3) == 'P')
        {
            p = strchr(tok, ' ');
            p = strchr(p + 1, ' ');
            *p = '\0';
            if (strcmp(tok, "HTTP/1.1 101") != 0 && strcmp(tok, "HTTP/1.0 101") != 0)
            {
                client->OnError(0, "Handshake failed, Response headers contained bad status");
                return nullptr;
            }

            client->flags |= REQUEST_VALID_STATUS;
        }
        else
        {
            p = strchr(tok, ' ');
            *p = '\0';
            if (strcasecmp(tok, "Upgrade:") == 0)
            {
                if (strcasecmp(p + 1, "websocket") == 0)
                {
                    client->flags |= REQUEST_HAS_UPGRADE;
                }
            }
            if (strcasecmp(tok, "Connection:") == 0)
            {
                if (strcasecmp(p + 1, "upgrade") == 0)
                {
                    client->flags |= REQUEST_HAS_CONNECTION;
                }
            }
            if (strcasecmp(tok, "Sec-WebSocket-Accept:") == 0)
            {
                if (strcmp(p + 1, respKey64) == 0)
                {
                    printf("[Websocket] Response key valid\n");
                    client->flags |= REQUEST_VALID_ACCEPT;
                }
            }
        }
    }

    if (!(client->flags & REQUEST_HAS_UPGRADE))
    {
        client->OnError(0, "Handshake failed, header had invalid/no upgrade field");
        return nullptr;
    }

    if (!(client->flags & REQUEST_HAS_CONNECTION))
    {
        client->OnError(0, "Handshake failed, header had no connection field");
        return nullptr;
    }

    if (!(client->flags & REQUEST_VALID_ACCEPT))
    {
        client->OnError(0, "Handshake failed, server sent invalid accept key");
        return nullptr;
    }

    pthread_mutex_lock(&client->lock);

    client->flags &= ~CLIENT_CONNECTING;

    pthread_mutex_unlock(&client->lock);

    client->OnOpen();

    printf("[Stop] Handshake thread\n");
    return nullptr;
}

int Websocket::Write(const void *buff, size_t size)
{
    if (flags & CLIENT_IS_SSL)
    {
        return mbedtls_ssl_write(&ssl, (unsigned char *)buff, size);
    }
    else
    {
        return send(sockfd, buff, size, 0);
    }
}

int Websocket::Read(void *buff, size_t size)
{
    if (flags & CLIENT_IS_SSL)
    {
        return mbedtls_ssl_read(&ssl, (unsigned char *)buff, size);
    }
    else
    {
        return recv(sockfd, (void *)buff, size, 0);
    }
}