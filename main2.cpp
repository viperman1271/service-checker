#include <libssh2.h>
#include <CLI/CLI.hpp>

#include <errno.h>
#include <iostream>
#include <regex>

#ifdef WIN32
#include <windows.h>
#pragma comment(lib, "ws2_32.lib")
#endif // WIN32

#if defined(__linux__)
#include <arpa/inet.h>
#include <netinet/in.h>
#include <resolv.h>
#include <sys/socket.h>
#include <unistd.h>
#endif // __linux__

#include <sstream>
#include <assert.h>

#define SERVICE_BIND_ERROR -1
#define SERVICE_BIND_FATAL_ERROR -2
#define SERVICE_BIND_RUNNING 1
#define SERVICE_BIND_STOPPED 2

std::string read_result(LIBSSH2_CHANNEL* channel)
{
    int bytecount = 0;
    int rc = 0;

    std::stringstream ss;

    do
    {
        char buffer[0x4000];
        rc = libssh2_channel_read(channel, buffer, sizeof(buffer));
        if (rc > 0)
        {
            bytecount += rc;
            std::cout << "we read: " << buffer << std::endl;
            ss << buffer;
        }
        else if (rc != LIBSSH2_ERROR_EAGAIN)
        {
            std::cerr << "libssh2_channel_read returned " << rc << std::endl;
        }
    } while (rc > 0);

    return ss.str();
}

LIBSSH2_CHANNEL* open_channel(LIBSSH2_SESSION* session)
{
    LIBSSH2_CHANNEL* channel = libssh2_channel_open_session(session);
    if (!channel)
    {
        std::cerr << "Unable to open a channel" << std::endl;
        libssh2_session_disconnect(session, "");
        libssh2_session_free(session);

        return nullptr;
    }

    return channel;
}

int is_bind_running(LIBSSH2_SESSION* session)
{
    LIBSSH2_CHANNEL* channel = open_channel(session);
    if (channel == nullptr)
    {
        return -1;
    }

    int rc = 0;
    if (rc = libssh2_channel_exec(channel, "service named status"))
    {
        std::cerr << "Unable to execute on a channel" << std::endl;

        libssh2_channel_close(channel);

        libssh2_session_disconnect(session, "");
        libssh2_session_free(session);

        return -1;
    }

    std::string rs = read_result(channel);

    if (rc = libssh2_channel_close(channel))
    {
        return SERVICE_BIND_ERROR;
    }

    if (rc == 0)
    {
        char* exitsignal = "none";
        auto exitcode = libssh2_channel_get_exit_status(channel);
        libssh2_channel_get_exit_signal(channel, &exitsignal, nullptr, nullptr, nullptr, nullptr, nullptr);
    }

    libssh2_channel_free(channel);
    channel = nullptr;

    std::regex running_regex("(named).*?(is running)", std::regex_constants::ECMAScript | std::regex_constants::icase);
    if (std::regex_search(rs, running_regex)) 
    {
        return SERVICE_BIND_RUNNING;
    }

    std::regex stopped_regex("(named).*?(is).*?(stopped)", std::regex_constants::ECMAScript | std::regex_constants::icase);
    if (std::regex_search(rs, stopped_regex))
    {
        return SERVICE_BIND_STOPPED;
    }

    return SERVICE_BIND_ERROR;
}

int start_bind(LIBSSH2_SESSION* session)
{
    LIBSSH2_CHANNEL* channel = open_channel(session);
    if (channel == nullptr)
    {
        return SERVICE_BIND_ERROR;
    }

    int rc = 0;
    if (rc = libssh2_channel_exec(channel, "service named start"))
    {
        std::cerr << "Unable to execute on a channel" << std::endl;

        libssh2_channel_close(channel);

        libssh2_session_disconnect(session, "");
        libssh2_session_free(session);

        return SERVICE_BIND_ERROR;
    }

    std::string rs = read_result(channel);


    if (rc = libssh2_channel_close(channel))
    {
        return SERVICE_BIND_ERROR;
    }

    if (rc == 0)
    {
        char* exitsignal = "none";
        auto exitcode = libssh2_channel_get_exit_status(channel);
        libssh2_channel_get_exit_signal(channel, &exitsignal, nullptr, nullptr, nullptr, nullptr, nullptr);
    }

    libssh2_channel_free(channel);
    channel = nullptr;

    return SERVICE_BIND_RUNNING;
}

int main(int argc, char** argv)
{
    CLI::App app("Command line application for querying dns records from a specific server");

    std::string hostname;
    app.add_option("-s,--server", hostname, "SSH server address");

    CLI11_PARSE(app, argc, argv);

#ifdef WIN32
    WSADATA wsadata;
    int err;

    err = WSAStartup(MAKEWORD(2, 0), &wsadata);
    if (err != 0) 
    {
        std::cerr << "WSAStartup failed with error: " << err << std::endl;
        return 1;
    }
#endif //WIN32

    int rc;
    if (rc = libssh2_init(0))
    {
        std::cerr << "libssh2 initialization failed " << rc << std::endl;
        return 1;
    }

    unsigned long hostaddr;

    //TODO: Need to resolve host from name

    hostaddr = inet_addr(hostname.c_str());

    int sock = socket(AF_INET, SOCK_STREAM, 0);

    struct sockaddr_in sin;
    sin.sin_family = AF_INET;
    sin.sin_port = htons(22);
    sin.sin_addr.s_addr = hostaddr;
    if (connect(sock, reinterpret_cast<struct sockaddr*>(&sin), sizeof(struct sockaddr_in)) != 0) 
    {
        std::cerr << "failed to connect!" << std::endl;
        return -1;
    }

    LIBSSH2_SESSION* session = libssh2_session_init();
    if (session == nullptr)
    {
        return -1;
    }

    if (rc = libssh2_session_handshake(session, sock))
    {
        std::cerr << "Failure establishing SSH session: " << rc << std::endl;
        return -1;
    }

    const char* fingerprint = libssh2_hostkey_hash(session, LIBSSH2_HOSTKEY_HASH_SHA1);

    //TODO gather fingerprint

    const char* privkey_path = nullptr;
    const char* pubkey_path = nullptr;

#ifdef _WIN32
    LPCSTR privKey = "%userprofile%\\.ssh\\id_rsa";
    LPCSTR pubKey = "%userprofile%\\.ssh\\id_rsa.pub";

    LPSTR privKeyStr = reinterpret_cast<LPSTR>(alloca(256));
    LPSTR pubKeyStr = reinterpret_cast<LPSTR>(alloca(256));

    ExpandEnvironmentStrings(privKey, privKeyStr, 256);
    ExpandEnvironmentStrings(pubKey, pubKeyStr, 256);

    privkey_path = privKeyStr;
    pubkey_path = pubKeyStr;
#else
    privkey_path = "~/.ssh/id_rsa";
    pubkey_path = "~/.ssh/id_rsa.pub";
#endif // _WIN32

    if (rc = libssh2_userauth_publickey_fromfile(session, "root", pubkey_path, privkey_path, ""))
    {
        std::cerr << "\tAuthentication by public key failed " << rc << std::endl;
        libssh2_session_disconnect(session, "");
        libssh2_session_free(session);

        return -1;
    }

    rc = is_bind_running(session);

    if (rc == SERVICE_BIND_STOPPED)
    {
        rc = start_bind(session);
        if (rc != SERVICE_BIND_ERROR)
        {
            rc = is_bind_running(session);
        }
    }

    int result = (rc == SERVICE_BIND_RUNNING) ? 0 : -1;

    libssh2_session_disconnect(session, "normal shutdown");
    libssh2_session_free(session);

#ifdef WIN32
    closesocket(sock);
#else
    close(sock);
#endif

    libssh2_exit();

    return result;
}