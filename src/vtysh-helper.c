#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>

#define BGPD_VTYSH "/var/run/quagga/bgpd.vty"
#define BUF_SIZE 256

int main (int argc, char **argv) 
{
    int s;
    int r;
    int cont;
    struct sockaddr_un vty;
    char buf[BUF_SIZE];
    char rbuf[BUF_SIZE];
    char cmd[BUF_SIZE];
    char *pos, *bufpos;
    int flags;
    
    s = socket(AF_UNIX, SOCK_STREAM, 0);
    
    bzero(&vty, sizeof(vty));
    vty.sun_family = AF_UNIX;
    strcpy(vty.sun_path, BGPD_VTYSH);
    
    connect(s, (struct sockaddr *) &vty, sizeof(vty));
    
    flags = fcntl(s, F_GETFL, 0);
    flags |= O_NONBLOCK;
    fcntl(s, F_SETFL, flags);

    cont = 0;
    while ((r = read(fileno(stdin), buf, BUF_SIZE)) != 0) {
	bufpos = buf;
	while ((pos = strstr(bufpos, "\n"))) {
	    if (cont) {
		strncat(cmd, bufpos, (pos - bufpos));		
		cont = 0;
	    } else {
		strncpy(cmd, bufpos, (pos - bufpos));
		cmd[(pos - bufpos)] = '\0';
	    }
	    if (strlen(cmd)) {
		r = write(s, cmd, strlen(cmd));
		r += write(s, "\0", (512 - strlen(cmd)));
		usleep(10);
	    }

	    r = read(s, rbuf, BUF_SIZE);

	    bufpos = (pos + 1);
	}
	if ((bufpos - buf) < BUF_SIZE) {
	    strncpy(cmd, bufpos, (BUF_SIZE - (bufpos - buf)));
	    cmd[(BUF_SIZE - (bufpos - buf))] = '\0';
	    cont = 1;
	}
	memset(buf, 0, BUF_SIZE);
    }
    
    close(s);
    return 1;
}
