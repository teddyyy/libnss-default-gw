#include <errno.h>
#include <string.h>
#include <netdb.h>
#include <nss.h>

#include <netlink/addr.h>
#include <netlink/route/route.h>

#define ALIGN(x) (((x+sizeof(void*)-1)/sizeof(void*))*sizeof(void*))

inline size_t ADDRLEN (int proto) {
    return proto == AF_INET6 ? sizeof(struct in6_addr) : sizeof(struct in_addr);
}

static struct nl_addr *
find_default_gateway_addr(int family) {
        struct nl_cache* route_cache;
        struct nl_sock *sock;
        struct nl_object *obj;
        struct nl_addr *gw = NULL;
        int err;

        // Allocate a new netlink socket
        sock = nl_socket_alloc();

        err = nl_connect(sock, NETLINK_ROUTE);
        if (err) {
                nl_socket_free(sock);
                return NULL;
        }

        if (rtnl_route_alloc_cache(sock, family, 0, &route_cache)) {
                nl_close(sock);
                nl_socket_free(sock);
                return NULL;
        }

        for (obj = nl_cache_get_first(route_cache); obj; obj = nl_cache_get_next(obj)) {
                struct rtnl_route *route = (struct rtnl_route *)obj;

                // Ignore non target routes
                if (rtnl_route_get_family(route) != family) continue;

                // Find a default route
                if (nl_addr_get_prefixlen(rtnl_route_get_dst(route)) != 0) continue;

                // Assert a next hop
                if (rtnl_route_get_nnexthops(route) < 1) continue;

                // Found a gateway
                struct nl_addr *gw_ = rtnl_route_nh_get_gateway(rtnl_route_nexthop_n(route, 0));
                if (!gw_) continue;

                // Clone the address, as this one will be freed with the route cache (will it?)
                gw = nl_addr_clone(gw_);
                if (!gw) continue;

                break;

        }

        // Free the cache
        nl_cache_free(route_cache);

        // Close the socket first to release kernel memory
        nl_close(sock);

        // Finally destroy the netlink handle
        nl_socket_free(sock);

        return gw;
}


static enum nss_status
fill_default_gateway_addr(const char *name,
		          int af,
                          struct hostent * result,
                          char *buffer,
                          size_t buflen,
                          int *errnop,
                          int *h_errnop)
{
	size_t n, offset, size;
	char *addr, *hostname, *aliases, *addr_list;
	size_t alen;
	struct nl_addr *gw;

	if (af == AF_INET) {
		gw = find_default_gateway_addr(AF_INET);
	} else if (af == AF_INET6) {
		gw = find_default_gateway_addr(AF_INET6);
	} else {
		*errnop = EAFNOSUPPORT;
                *h_errnop = NO_RECOVERY;
                return NSS_STATUS_UNAVAIL;
	}

	if (!gw) {
		*errnop = EAGAIN;
		*h_errnop = NO_RECOVERY;
		return NSS_STATUS_TRYAGAIN;
	}

	alen = ADDRLEN(af);

	n = strlen(name) + 1;
	size = ALIGN(n) + sizeof(char*) + ALIGN(alen) + sizeof(char*) * 2;
	if (buflen < size) {
		nl_addr_put(gw);

		*errnop = ENOMEM;
		*h_errnop = NO_RECOVERY;
		return NSS_STATUS_TRYAGAIN;
	}

	// hostname
	hostname = buffer;
	memcpy(hostname, name, n);
	offset = ALIGN(n);

	// aliase
	aliases = buffer + offset;
	*(char**) aliases = NULL;
	offset += sizeof(char*);

	// address
	addr = buffer + offset;
	if (af == AF_INET)
		memcpy(addr, nl_addr_get_binary_addr(gw), sizeof(struct in_addr));
	else
		memcpy(addr, nl_addr_get_binary_addr(gw), sizeof(struct in6_addr));

	offset += ALIGN(alen);

	// address list
	addr_list = buffer + offset;
	((char**) addr_list)[0] = addr;
	((char**) addr_list)[1] = NULL;
	offset += sizeof(char*) * 2;

	result->h_name = hostname;
	result->h_aliases = (char**) aliases;
	result->h_addrtype = af;
	result->h_length = alen;
	result->h_addr_list = (char**) addr_list;

	nl_addr_put(gw);


	return NSS_STATUS_SUCCESS;
}

enum nss_status
_nss_default_gw_gethostbyname3_r(const char *name,
				 int af,
				 struct hostent * result,
	                         char *buffer,
	                         size_t buflen,
	                         int *errnop,
	                         int *h_errnop,
				 int32_t *ttlp,
				 char **canonp)
{
	if (af == AF_UNSPEC)
		af = AF_INET;

	if (strcmp(name, "dgw") == 0) {
		return fill_default_gateway_addr(name,
						 af,
				                 result,
					         buffer,
					         buflen,
					         errnop,
                                                 h_errnop);
	} else {
		*errnop = EINVAL;
		*h_errnop = NO_RECOVERY;
		return NSS_STATUS_UNAVAIL;
	}
}

enum nss_status
_nss_default_gw_gethostbyname2_r(const char *name,
				int af,
				struct hostent * result,
	                        char *buffer,
	                        size_t buflen,
	                        int *errnop,
	                        int *h_errnop)
{
	return _nss_default_gw_gethostbyname3_r(name,
                                                AF_UNSPEC,
                                                result,
                                                buffer,
						buflen,
						errnop,
						h_errnop,
						NULL,
						NULL);
}


enum nss_status
_nss_default_gw_gethostbyname_r(const char *name,
				struct hostent * result,
	                        char *buffer,
	                        size_t buflen,
	                        int *errnop,
	                        int *h_errnop)
{
	return _nss_default_gw_gethostbyname2_r(name,
                                                AF_UNSPEC,
                                                result,
                                                buffer,
						buflen,
						errnop,
						h_errnop);
}

