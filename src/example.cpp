#include <stdio.h>

#include "websocket.h"

class MyClient : public Websocket
{
public:
    int a;

    MyClient():Websocket("wss://ws.postman-echo.com/raw")
    {

    }

    ~MyClient()
    {

    }

    void OnOpen() override
    {
        printf("Opened!\n");
        
        SendControlFrame(PING);
        SendMessage("Start");
        a = 0;
    }

    void OnClose() override
    {

    }

    void OnError(int code, std::string error) override
    {
        printf("Error: %s (%x)\n", error.c_str(), code);
    }

    void OnMessage(std::string& message, unsigned char opcode) override
    {
        printf("[Websocket] Received message: %s\n", message.c_str());
        a++;

        if(a % 5 == 0)
        {
            SendControlFrame(PING);
        }
        else if(a == 101)
        {
            SendControlFrame(CLOSE);
        }

        char buff[10];
        snprintf(buff, sizeof(buff), "%d", a);

        SendMessage(buff);
    }
};

int main()
{
    printf("Hello world!\n");

    auto c = MyClient();

    c.Connect();
    c.StartProcessing();
    c.WaitEnd();

    return 0;
}