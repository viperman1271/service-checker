//#include <libssh/libssh.h>
#include <libssh2.h>
#include <errno.h>
#include <iostream>
#include <regex>

#include <windows.h>

#include <sstream>
#include <assert.h>

#define SERVICE_BIND_ERROR -1
#define SERVICE_BIND_FATAL_ERROR -100
#define SERVICE_BIND_RUNNING 1
#define SERVICE_BIND_STOPPED 0

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

int main()
{
    LIBSSH2_SESSION* session = libssh2_session_init();

//     ssh_session session = ssh_new();
//     if (session == nullptr)
//     {
//         return -1;
//     }
// 
//     int verbosity = SSH_LOG_PROTOCOL;
//     int port = 22;
// 
//     ssh_options_set(session, SSH_OPTIONS_HOST, "ns1.mikefilion.com");
//     ssh_options_set(session, SSH_OPTIONS_LOG_VERBOSITY, &verbosity);
//     ssh_options_set(session, SSH_OPTIONS_PORT, &port);
// 
//     int rc = ssh_connect(session);
//     if (rc != SSH_OK)
//     {
//         char* value = reinterpret_cast<char*>(alloca(256));
//         ssh_options_get(session, SSH_OPTIONS_HOST, &value);
//         std::cerr << "Error connecting to" << value <<  ": " << ssh_get_error(session) << std::endl;
//         return -1;
//     }
// 
//     int state = ssh_is_server_known(session);
//     switch (state) 
//     {
//     case SSH_SERVER_KNOWN_OK:
//         break;
// 
//     case SSH_SERVER_ERROR:
//     case SSH_SERVER_KNOWN_CHANGED:
//     case SSH_SERVER_NOT_KNOWN:
//         return -1;
//     }
// 
//     const char* pubkey_path = nullptr;
// #ifdef _WIN32
//     LPCSTR blah = "%userprofile%\\.ssh\\id_rsa";
//     LPSTR str = reinterpret_cast<LPSTR>(alloca(256));
// 
//     ExpandEnvironmentStrings(blah, str, 256);
// 
//     pubkey_path = str;
// #else
//     #pragma error("Not implemented")
// #endif // _WIN32
// 
//     ssh_key pkey;
//     rc = ssh_pki_import_privkey_file(pubkey_path, nullptr, nullptr, nullptr, &pkey);
//     if (rc != SSH_OK)
//     {
//         return -1;
//     }
// 
//     rc = ssh_userauth_publickey(session, "root", pkey);
//     if (rc != SSH_AUTH_SUCCESS)
//     {
//         std::cerr << "Error authenticating with publickey: " << ssh_get_error(session) << std::endl;
//         ssh_disconnect(session);
//         ssh_free(session);
//         return -1;
//     }
// 
//     switch (is_bind_running2(session))
//     {
//         case SERVICE_BIND_FATAL_ERROR:
//             return -1;
// 
//         case SERVICE_BIND_STOPPED:
//             start_bind2(session);
//             break;
//     }
// 
//     ssh_disconnect(session);
//     ssh_free(session);

    return 0;
}