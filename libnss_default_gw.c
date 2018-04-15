#include <errno.h>
#include <string.h>

#include <netdb.h>
#include <nss.h>

#include "internal.h"
#include "external.h"

static enum nss_status
fill_default_gw_ip4addr(const char *name,
                        struct hostent * result,
                        char *buffer,
                        size_t buflen,
                        int *errnop,
                        int *h_errnop) {

	if (!strcmp(name, "gw.internal") || !strcmp(name, "gw.external")) {
		*errnop = EINVAL;
                *h_errnop = NO_RECOVERY;
                return NSS_STATUS_UNAVAIL;
	}

	if (strcmp(name, "gw.internal"))
		fill_default_internal_gw_ip4addr();
	else if(strcmp(name, "gw.external"))
		fill_default_external_gw_ip4addr();

	return NSS_STATUS_SUCCESS;
}

static enum nss_status
fill_default_gw_ip6addr(const char *name,
                        struct hostent * result,
                        char *buffer,
                        size_t buflen,
                        int *errnop,
                        int *h_errnop) {

	if (!strcmp(name, "gw.internal") || !strcmp(name, "gw.external")) {
		*errnop = EINVAL;
                *h_errnop = NO_RECOVERY;
                return NSS_STATUS_UNAVAIL;
	}

	if (strcmp(name, "gw.internal"))
		fill_default_internal_gw_ip6addr();
	else if (strcmp(name, "gw.external"))
		fill_default_external_gw_ip6addr();

	return NSS_STATUS_SUCCESS;
}

enum nss_status
_nss_default_gw_gethostbyname2_r(const char *name,
				 int af,
				 struct hostent * result,
	                         char *buffer,
	                         size_t buflen,
	                         int *errnop,
	                         int *h_errnop) {

	if (af == AF_UNSPEC)
		af = AF_INET;

	if (af == AF_INET) {
		return fill_default_gw_ip4addr(name,
				               result,
					       buffer,
					       buflen,
					       errnop,
                                               h_errnop);
	} else if (af == AF_INET6) {
		return fill_default_gw_ip6addr(name,
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
_nss_default_gw_gethostbyname_r(const char *name,
				struct hostent * result,
	                        char *buffer,
	                        size_t buflen,
	                        int *errnop,
	                        int *h_errnop) {

	return _nss_default_gw_gethostbyname2_r(name,
                                                AF_UNSPEC,
                                                result,
                                                buffer,
						buflen,
						errnop,
						h_errnop);
}


