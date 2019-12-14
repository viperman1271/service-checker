#include <libssh2.h>
#include <CLI/CLI.hpp>

#include <errno.h>
#include <iostream>
#include <regex>

#ifdef PLATFORM_WINDOWS
#include <windows.h>
#endif // PLATFORM_WINDOWS

#ifdef PLATFORM_UNIX
#include <arpa/inet.h>
#include <netinet/in.h>
#include <resolv.h>
#include <sys/socket.h>
#include <unistd.h>
#endif // PLATFORM_UNIX

#include <sstream>
#include <assert.h>

#define SERVICE_BIND_ERROR -1
#define SERVICE_BIND_FATAL_ERROR -2
#define SERVICE_BIND_RUNNING 1
#define SERVICE_BIND_STOPPED 2

std::vector<std::string> split_string(const std::string& str)
{
    std::stringstream ss(str);

    std::vector<std::string> vector;
    std::string val;
    while (std::getline(ss, val, '\n'))
    {
        vector.push_back(val);
    }
    return vector;
}

std::string read_result(LIBSSH2_CHANNEL* channel)
{
    int bytecount = 0;
    int rc = 0;

    std::stringstream ss;

    do
    {
        char buffer[0x4000];
        memset(buffer, 0, sizeof(buffer));
        rc = static_cast<int>(libssh2_channel_read(channel, buffer, sizeof(buffer)));
        if (rc > 0)
        {
            bytecount += rc;
            ss << buffer;
        }
        else if (rc == 0)
        {
            /*Do nothing*/
        }
        else if (rc != LIBSSH2_ERROR_EAGAIN)
        {
            std::cerr << "libssh2_channel_read returned: " << rc << std::endl;
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
        std::cerr << "Unable to execute on a channel " << rc << std::endl;

        libssh2_channel_close(channel);

        libssh2_session_disconnect(session, "");
        libssh2_session_free(session);

        return -1;
    }

    std::string rs = read_result(channel);
    std::vector<std::string> lines = split_string(rs);

    if (rc = libssh2_channel_close(channel))
    {
        std::cerr << "Unable to close channel " << rc << std::endl;

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

    for (const std::string& line : lines)
    {
        const bool isRunningFound = (line.find("running") != std::string::npos);
        const bool isStoppedFound = (line.find("stopped") != std::string::npos);
        const bool isDead = (line.find(" dead ") != std::string::npos);
        const bool namedFound = (line.find("named") != std::string::npos);

        if (namedFound && isRunningFound)
        {
            return SERVICE_BIND_RUNNING;
        }
        else if (namedFound && (isStoppedFound || isDead))
        {
            return SERVICE_BIND_STOPPED;
        }
    }

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
        std::cerr << "Unable to execute on a channel " << rc << std::endl;

        libssh2_channel_close(channel);

        libssh2_session_disconnect(session, "");
        libssh2_session_free(session);

        return SERVICE_BIND_ERROR;
    }

    std::string rs = read_result(channel);


    if (rc = libssh2_channel_close(channel))
    {
        std::cerr << "Unable to close channel " << rc << std::endl;
        return SERVICE_BIND_ERROR;
    }

    if (rc == 0)
    {
        char* exitsignal = static_cast<char*>("none");
        auto exitcode = libssh2_channel_get_exit_status(channel);
        libssh2_channel_get_exit_signal(channel, &exitsignal, nullptr, nullptr, nullptr, nullptr, nullptr);
    }

    libssh2_channel_free(channel);
    channel = nullptr;

    if (rc == 0)
    {
        return is_bind_running(session);
    }

    return SERVICE_BIND_ERROR;
}

int main(int argc, char** argv)
{
    CLI::App app("Command line application for querying dns records from a specific server");

    std::string hostname;
    std::string pubkey;
    std::string privkey;
    bool verbose = false;
    app.add_option("-s,--server", hostname, "SSH server address");
    app.add_option("--pub", pubkey, "Specify a path to override the default public key path");
    app.add_option("--priv", privkey, "Override the default private key path with the provided path");
    app.add_flag("-v,--verbose", verbose, "Whether the output shall be verbose or not");

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

    /*TODO: Need to resolve host from name*/

    const unsigned long hostaddr = inet_addr(hostname.c_str());

    auto sock = socket(AF_INET, SOCK_STREAM, 0);

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
        std::cerr << "failed to initialize session!" << std::endl;
        return -1;
    }

    if (rc = libssh2_session_handshake(session, sock))
    {
        std::cerr << "Failure establishing SSH session: " << rc << std::endl;
        return -1;
    }

    const char* fingerprint = libssh2_hostkey_hash(session, LIBSSH2_HOSTKEY_HASH_SHA1);

    if (verbose)
    {
        std::cout << "Remote server fingerprint: " << fingerprint << std::endl;
    }

    /*TODO gather fingerprint*/

#ifdef _WIN32
    if (privkey.empty())
    {
        LPCSTR privKeyTemp = "%userprofile%\\.ssh\\id_rsa";
        LPSTR privKeyStr = reinterpret_cast<LPSTR>(alloca(256));
        ExpandEnvironmentStrings(privKeyTemp, privKeyStr, 256);
        privkey = privKeyStr;
    }

    if (pubkey.empty())
    {
        LPCSTR pubKeyTemp = "%userprofile%\\.ssh\\id_rsa.pub";
        LPSTR pubKeyStr = reinterpret_cast<LPSTR>(alloca(256));
        ExpandEnvironmentStrings(pubKeyTemp, pubKeyStr, 256);
        pubkey = pubKeyStr;
    }
#else
    if (privkey.empty())
    {
        privkey = "~/.ssh/id_rsa";
    }
    if (pubkey.empty())
    {
        pubkey = "~/.ssh/id_rsa.pub";
    }
#endif // _WIN32

    if (verbose)
    {
        std::cout << "Public key path: " << pubkey << std::endl;
        std::cout << "Private key path: " << privkey << std::endl;
    }

    if (rc = libssh2_userauth_publickey_fromfile(session, "root", pubkey.c_str(), privkey.c_str(), ""))
    {
        std::cerr << "\tAuthentication by public key failed " << rc << " [pub: " << pubkey << ", priv: " << privkey << "]" << std::endl;
        libssh2_session_disconnect(session, "");
        libssh2_session_free(session);

        return -1;
    }

    rc = is_bind_running(session);
    if (rc == SERVICE_BIND_STOPPED)
    {
        if (verbose) { std::cout << "bind was not running" << std::endl; }

        rc = start_bind(session);

        if (verbose) 
        { 
            switch (rc)
            {
            case SERVICE_BIND_RUNNING:
                std::cout << "bind service was started" << std::endl;
                break;

            default:
                std::cout << "bind service could not be started" << std::endl;
                break;
            }
        }
    }

    const int result = (rc == SERVICE_BIND_RUNNING) ? 0 : -1;
    if (verbose)
    {
        std::cout << "result: " << result << std::endl;
    }

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