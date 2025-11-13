#ifndef CONFIG_H
# define CONFIG_H

# define DEBUG_OUTPUT 0 // change to 1 to enable debugging

# define _GNU_SOURCE 1 // required to use secure_getenv

# define PKCS11PROXY_LISTEN_BACKLOG 128
# define PKCS11PROXY_MAX_SESSION_COUNT 256

# define PKCS11PROXY_TLS_PSK_CIPHERS "TLS_ECDHE_PSK_WITH_AES_128_GCM_SHA256:TLS_ECDHE_PSK_WITH_AES_256_GCM_SHA384:TLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256";

//# define DEBUG_SECCOMP
//# define SECCOMP

#ifdef __APPLE__
# define MSG_NOSIGNAL SO_NOSIGPIPE
#endif

#ifdef __MINGW32__

# include <stdint.h>
# include <stdlib.h>
# include <limits.h>
# include <winsock2.h>

typedef uint32_t __uid32_t;
typedef uint32_t __gid32_t;
typedef uint32_t uid_t;
typedef int socklen_t;

struct sockaddr_un {
	uint16_t sun_family;
	char sun_path[PATH_MAX];
};

enum  {
	SHUT_RD = 0, /* No more receptions.  */
	SHUT_WR, /* No more transmissions.  */
	SHUT_RDWR /* No more receptions or transmissions.  */
};

static inline int inet_aton(const char * cp, struct in_addr *pin)
{
        int rc = inet_addr(cp);
        if (rc == -1 && strcmp(cp, "255.255.255.255"))
                return 0;

        pin->s_addr = rc;
        return 1;
}

#endif

#endif	/* CONFIG_H */
