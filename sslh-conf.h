/* Generated by conf2struct (https://www.rutschle.net/tech/conf2struct/README)
 * on Sat Mar  9 12:35:49 2019. */
 
#ifndef C2S_SSLHCFG_H
#define C2S_SSLHCFG_H
#include <libconfig.h>

#include "probe.h"
#include  <sys/types.h>
#include  <sys/socket.h>
#include  <netdb.h>

struct sslhcfg_listen_item {
	char*	host;
	char*	port;
	int	keepalive;
};

struct sslhcfg_protocols_item {
	const char*	name;
	char*	host;
	char*	port;
	int	service_is_present;
	const char*	service;
	int	fork;
	int	log_level;
	int	keepalive;
	size_t	sni_hostnames_len;
	const char** sni_hostnames;
	size_t	alpn_protocols_len;
	const char** alpn_protocols;
	size_t	regex_patterns_len;
	const char** regex_patterns;
	int	minlength_is_present;
	int	minlength;
	T_PROBE*	probe;
	struct addrinfo*	saddr;
	void*	data;
};

struct sslhcfg_item {
	int	verbose;
	int	foreground;
	int	inetd;
	int	numeric;
	int	transparent;
	int	timeout;
	int	user_is_present;
	const char*	user;
	int	pidfile_is_present;
	const char*	pidfile;
	int	chroot_is_present;
	const char*	chroot;
	const char*	syslog_facility;
	const char*	on_timeout;
	size_t	listen_len;
	struct sslhcfg_listen_item* listen;
	size_t	protocols_len;
	struct sslhcfg_protocols_item* protocols;
};

int sslhcfg_parse_file(
        const char* filename,
        struct sslhcfg_item* sslhcfg, 
        const char** errmsg);

void sslhcfg_fprint(
    FILE* out,
    struct sslhcfg_item *sslhcfg,
    int depth);

int sslhcfg_cl_parse(
    int argc,
    char* argv[],
    struct sslhcfg_item *sslhcfg);

#endif
