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
#define SERVICE_BIND_FATAL_ERROR -100
#define SERVICE_BIND_RUNNING 1
#define SERVICE_BIND_STOPPED 0

static int waitsocket(int socket_fd, LIBSSH2_SESSION *session)
{
    struct timeval timeout;
    int rc;
    fd_set fd;
    fd_set *writefd = nullptr;
    fd_set *readfd = nullptr;
    int dir;

    timeout.tv_sec = 10;
    timeout.tv_usec = 0;

    FD_ZERO(&fd);

    FD_SET(socket_fd, &fd);

    /* now make sure we wait in the correct direction */
    dir = libssh2_session_block_directions(session);

    if (dir & LIBSSH2_SESSION_BLOCK_INBOUND)
        readfd = &fd;

    if (dir & LIBSSH2_SESSION_BLOCK_OUTBOUND)
        writefd = &fd;

    rc = select(socket_fd + 1, readfd, writefd, nullptr, &timeout);

    return rc;
}

int is_bind_running2(/*ssh_session session*/)
{
//     ssh_channel channel = ssh_channel_new(session);
//     if (channel == nullptr)
//     {
//         ssh_disconnect(session);
//         ssh_free(session);
// 
//         return SERVICE_BIND_FATAL_ERROR;
//     }
// 
//     int rc = ssh_channel_open_session(channel);
//     if (rc != SSH_OK)
//     {
//         ssh_channel_free(channel);
//         return rc;
//     }
// 
//     rc = ssh_channel_request_exec(channel, "service named status");
//     if (rc != SSH_OK)
//     {
//         std::cerr << "Error requesting exec: " << ssh_get_error(session) << std::endl;
// 
//         ssh_channel_close(channel);
//         ssh_channel_free(channel);
//         return rc;
//     }
// 
//     std::stringstream ss;
// 
//     int nbytes;
//     char buffer[1024];
//     memset(buffer, 0, sizeof(buffer));
// 
//     nbytes = ssh_channel_read(channel, buffer, sizeof(buffer), 0);
//     while (nbytes > 0)
//     {
//         ss << buffer;
//         memset(buffer, 0, sizeof(buffer));
//         nbytes = ssh_channel_read(channel, buffer, sizeof(buffer), 0);
//     }
// 
//     ssh_channel_send_eof(channel);
//     ssh_channel_close(channel);
//     ssh_channel_free(channel);
// 
//     std::regex running_regex("(named).*?(is running)", std::regex_constants::ECMAScript | std::regex_constants::icase);
//     if (std::regex_search(ss.str(), running_regex)) 
//     {
//         return SERVICE_BIND_RUNNING;
//     }
// 
//     std::regex stopped_regex("(named).*?(is).*?(stopped)", std::regex_constants::ECMAScript | std::regex_constants::icase);
//     if (std::regex_search(ss.str(), stopped_regex))
//     {
//         return SERVICE_BIND_STOPPED;
//     }

    return SERVICE_BIND_ERROR;
}

int start_bind2(/*ssh_session session*/)
{
//     ssh_channel channel = ssh_channel_new(session);
//     if (channel == nullptr)
//     {
//         ssh_disconnect(session);
//         ssh_free(session);
// 
//         return SERVICE_BIND_FATAL_ERROR;
//     }
// 
//     int rc = ssh_channel_open_session(channel);
//     if (rc != SSH_OK)
//     {
//         ssh_channel_free(channel);
// 
//         return rc;
//     }
// 
//     rc = ssh_channel_request_exec(channel, "service named start");
//     if (rc != SSH_OK)
//     {
//         std::cerr << "Error requesting exec: " << ssh_get_error(session) << std::endl;
// 
//         ssh_channel_close(channel);
//         ssh_channel_free(channel);
// 
//         return rc;
//     }
// 
//     std::stringstream ss;
// 
//     int nbytes;
//     char buffer[1024];
//     memset(buffer, 0, sizeof(buffer));
// 
//     nbytes = ssh_channel_read(channel, buffer, sizeof(buffer), 0);
//     while (nbytes > 0)
//     {
//         ss << buffer;
//         memset(buffer, 0, sizeof(buffer));
//         nbytes = ssh_channel_read(channel, buffer, sizeof(buffer), 0);
//     }
// 
//     ssh_channel_send_eof(channel);
//     ssh_channel_close(channel);
//     ssh_channel_free(channel);

    return 0;
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
    if (connect(sock, (struct sockaddr*)(&sin), sizeof(struct sockaddr_in)) != 0) 
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
    #pragma error("Not implemented")
#endif // _WIN32

    if (libssh2_userauth_publickey_fromfile(session, "root", pubkey_path, privkey_path, "")) 
    {
        std::cerr << "\tAuthentication by public key failed" << std::endl;
        libssh2_session_disconnect(session, "");
        libssh2_session_free(session);

        return -1;
    }

    LIBSSH2_CHANNEL* channel = libssh2_channel_open_session(session);
    if (!channel) 
    {
        std::cerr << "Unable to open a session" << std::endl;
        libssh2_session_disconnect(session, "");
        libssh2_session_free(session);

        return -1;
    }

    while ((rc = libssh2_channel_exec(channel, "service named status")) == LIBSSH2_ERROR_EAGAIN) 
    {
        waitsocket(sock, session);
    }

    //////////////////////////////////////////////////////////////////////////

    int bytecount = 0;

    for (;;) {
        /* loop until we block */
        int rc;
        do {
            char buffer[0x4000];
            rc = libssh2_channel_read(channel, buffer, sizeof(buffer));
            if (rc > 0) 
            {
                int i;
                bytecount += rc;

                std::cout << "we read: " << buffer << std::endl;

//                 fprintf(stderr, "We read:\n");
//                 for (i = 0; i < rc; ++i)
//                 {
//                     fputc(buffer[i], stderr);
//                 }
//                 fprintf(stderr, "\n");
            }
            else 
            {
                if (rc != LIBSSH2_ERROR_EAGAIN)
                {
                    std::cerr << "libssh2_channel_read returned " << rc << std::endl;
                }
            }
        } while (rc > 0);

        /* this is due to blocking that would occur otherwise so we loop on
           this condition */
        if (rc == LIBSSH2_ERROR_EAGAIN) {
            waitsocket(sock, session);
        }
        else
            break;
    }

    //////////////////////////////////////////////////////////////////////////

    while ((rc = libssh2_channel_close(channel)) == LIBSSH2_ERROR_EAGAIN)
    {
        waitsocket(sock, session);
    }

    char* exitsignal = (char*)"none";

    if (rc == 0) 
    {
        auto exitcode = libssh2_channel_get_exit_status(channel);
        libssh2_channel_get_exit_signal(channel, &exitsignal, nullptr, nullptr, nullptr, nullptr, nullptr);
    }

    libssh2_channel_free(channel);
    channel = nullptr;

    libssh2_session_disconnect(session, "normal shutdown");
    libssh2_session_free(session);

#ifdef WIN32
    closesocket(sock);
#else
    close(sock);
#endif

    libssh2_exit();

    return 0;
}