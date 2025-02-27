// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2020, Tessares SA. */
/* Copyright (c) 2022, SUSE. */

#include <linux/const.h>
#include <netinet/in.h>
#include <test_progs.h>
#include "cgroup_helpers.h"
#include "network_helpers.h"
#include "mptcp_sock.skel.h"
#include "mptcpify.skel.h"
#include "mptcp_subflow.skel.h"
#include "mptcp_bpf_first.skel.h"
#include "mptcp_bpf_bkup.skel.h"
#include "mptcp_bpf_rr.skel.h"
#include "mptcp_bpf_red.skel.h"
#include "mptcp_bpf_burst.skel.h"

#define NS_TEST "mptcp_ns"
#define ADDR_1	"10.0.1.1"
#define ADDR_2	"10.0.1.2"
#define PORT_1	10001
#define WITH_DATA	true
#define WITHOUT_DATA	false

#ifndef IPPROTO_MPTCP
#define IPPROTO_MPTCP 262
#endif

#ifndef SOL_MPTCP
#define SOL_MPTCP 284
#endif
#ifndef MPTCP_INFO
#define MPTCP_INFO		1
#endif
#ifndef MPTCP_INFO_FLAG_FALLBACK
#define MPTCP_INFO_FLAG_FALLBACK		_BITUL(0)
#endif
#ifndef MPTCP_INFO_FLAG_REMOTE_KEY_RECEIVED
#define MPTCP_INFO_FLAG_REMOTE_KEY_RECEIVED	_BITUL(1)
#endif

#ifndef TCP_CA_NAME_MAX
#define TCP_CA_NAME_MAX	16
#endif
#define MPTCP_SCHED_NAME_MAX	16

static const unsigned int total_bytes = 10 * 1024 * 1024;
static int stop, duration;

struct __mptcp_info {
	__u8	mptcpi_subflows;
	__u8	mptcpi_add_addr_signal;
	__u8	mptcpi_add_addr_accepted;
	__u8	mptcpi_subflows_max;
	__u8	mptcpi_add_addr_signal_max;
	__u8	mptcpi_add_addr_accepted_max;
	__u32	mptcpi_flags;
	__u32	mptcpi_token;
	__u64	mptcpi_write_seq;
	__u64	mptcpi_snd_una;
	__u64	mptcpi_rcv_nxt;
	__u8	mptcpi_local_addr_used;
	__u8	mptcpi_local_addr_max;
	__u8	mptcpi_csum_enabled;
	__u32	mptcpi_retransmits;
	__u64	mptcpi_bytes_retrans;
	__u64	mptcpi_bytes_sent;
	__u64	mptcpi_bytes_received;
	__u64	mptcpi_bytes_acked;
};

struct mptcp_storage {
	__u32 invoked;
	__u32 is_mptcp;
	struct sock *sk;
	__u32 token;
	struct sock *first;
	char ca_name[TCP_CA_NAME_MAX];
};

static void sig_int(int sig)
{
	signal(sig, SIG_IGN);
	SYS_NOFAIL("ip netns del %s", NS_TEST);
}

static struct nstoken *create_netns(void)
{
	SYS(fail, "ip netns add %s", NS_TEST);
	SYS(fail, "ip -net %s link set dev lo up", NS_TEST);

	signal(SIGINT, sig_int);
	return open_netns(NS_TEST);
fail:
	return NULL;
}

static void cleanup_netns(struct nstoken *nstoken)
{
	if (nstoken)
		close_netns(nstoken);

	SYS_NOFAIL("ip netns del %s", NS_TEST);
}

static int verify_tsk(int map_fd, int client_fd)
{
	int err, cfd = client_fd;
	struct mptcp_storage val;

	err = bpf_map_lookup_elem(map_fd, &cfd, &val);
	if (!ASSERT_OK(err, "bpf_map_lookup_elem"))
		return err;

	if (!ASSERT_EQ(val.invoked, 1, "unexpected invoked count"))
		err++;

	if (!ASSERT_EQ(val.is_mptcp, 0, "unexpected is_mptcp"))
		err++;

	return err;
}

static void get_msk_ca_name(char ca_name[])
{
	size_t len;
	int fd;

	fd = open("/proc/sys/net/ipv4/tcp_congestion_control", O_RDONLY);
	if (!ASSERT_GE(fd, 0, "failed to open tcp_congestion_control"))
		return;

	len = read(fd, ca_name, TCP_CA_NAME_MAX);
	if (!ASSERT_GT(len, 0, "failed to read ca_name"))
		goto err;

	if (len > 0 && ca_name[len - 1] == '\n')
		ca_name[len - 1] = '\0';

err:
	close(fd);
}

static int verify_msk(int map_fd, int client_fd, __u32 token)
{
	char ca_name[TCP_CA_NAME_MAX];
	int err, cfd = client_fd;
	struct mptcp_storage val;

	if (!ASSERT_GT(token, 0, "invalid token"))
		return -1;

	get_msk_ca_name(ca_name);

	err = bpf_map_lookup_elem(map_fd, &cfd, &val);
	if (!ASSERT_OK(err, "bpf_map_lookup_elem"))
		return err;

	if (!ASSERT_EQ(val.invoked, 1, "unexpected invoked count"))
		err++;

	if (!ASSERT_EQ(val.is_mptcp, 1, "unexpected is_mptcp"))
		err++;

	if (!ASSERT_EQ(val.token, token, "unexpected token"))
		err++;

	if (!ASSERT_EQ(val.first, val.sk, "unexpected first"))
		err++;

	if (!ASSERT_STRNEQ(val.ca_name, ca_name, TCP_CA_NAME_MAX, "unexpected ca_name"))
		err++;

	return err;
}

static int run_test(int cgroup_fd, int server_fd, bool is_mptcp)
{
	int client_fd, prog_fd, map_fd, err;
	struct mptcp_sock *sock_skel;

	sock_skel = mptcp_sock__open_and_load();
	if (!ASSERT_OK_PTR(sock_skel, "skel_open_load"))
		return libbpf_get_error(sock_skel);

	err = mptcp_sock__attach(sock_skel);
	if (!ASSERT_OK(err, "skel_attach"))
		goto out;

	prog_fd = bpf_program__fd(sock_skel->progs._sockops);
	map_fd = bpf_map__fd(sock_skel->maps.socket_storage_map);
	err = bpf_prog_attach(prog_fd, cgroup_fd, BPF_CGROUP_SOCK_OPS, 0);
	if (!ASSERT_OK(err, "bpf_prog_attach"))
		goto out;

	client_fd = connect_to_fd(server_fd, 0);
	if (!ASSERT_GE(client_fd, 0, "connect to fd")) {
		err = -EIO;
		goto out;
	}

	err += is_mptcp ? verify_msk(map_fd, client_fd, sock_skel->bss->token) :
			  verify_tsk(map_fd, client_fd);

	close(client_fd);

out:
	mptcp_sock__destroy(sock_skel);
	return err;
}

static void test_base(void)
{
	struct nstoken *nstoken = NULL;
	int server_fd, cgroup_fd;

	cgroup_fd = test__join_cgroup("/mptcp");
	if (!ASSERT_GE(cgroup_fd, 0, "test__join_cgroup"))
		return;

	nstoken = create_netns();
	if (!ASSERT_OK_PTR(nstoken, "create_netns"))
		goto fail;

	/* without MPTCP */
	server_fd = start_server(AF_INET, SOCK_STREAM, NULL, 0, 0);
	if (!ASSERT_GE(server_fd, 0, "start_server"))
		goto with_mptcp;

	ASSERT_OK(run_test(cgroup_fd, server_fd, false), "run_test tcp");

	close(server_fd);

with_mptcp:
	/* with MPTCP */
	server_fd = start_mptcp_server(AF_INET, NULL, 0, 0);
	if (!ASSERT_GE(server_fd, 0, "start_mptcp_server"))
		goto fail;

	ASSERT_OK(run_test(cgroup_fd, server_fd, true), "run_test mptcp");

	close(server_fd);

fail:
	cleanup_netns(nstoken);
	close(cgroup_fd);
}

static void send_byte(int fd)
{
	char b = 0x55;

	ASSERT_EQ(write(fd, &b, sizeof(b)), 1, "send single byte");
}

static int verify_mptcpify(int server_fd, int client_fd)
{
	struct __mptcp_info info;
	socklen_t optlen;
	int protocol;
	int err = 0;

	optlen = sizeof(protocol);
	if (!ASSERT_OK(getsockopt(server_fd, SOL_SOCKET, SO_PROTOCOL, &protocol, &optlen),
		       "getsockopt(SOL_PROTOCOL)"))
		return -1;

	if (!ASSERT_EQ(protocol, IPPROTO_MPTCP, "protocol isn't MPTCP"))
		err++;

	optlen = sizeof(info);
	if (!ASSERT_OK(getsockopt(client_fd, SOL_MPTCP, MPTCP_INFO, &info, &optlen),
		       "getsockopt(MPTCP_INFO)"))
		return -1;

	if (!ASSERT_GE(info.mptcpi_flags, 0, "unexpected mptcpi_flags"))
		err++;
	if (!ASSERT_FALSE(info.mptcpi_flags & MPTCP_INFO_FLAG_FALLBACK,
			  "MPTCP fallback"))
		err++;
	if (!ASSERT_TRUE(info.mptcpi_flags & MPTCP_INFO_FLAG_REMOTE_KEY_RECEIVED,
			 "no remote key received"))
		err++;

	return err;
}

static int run_mptcpify(int cgroup_fd)
{
	int server_fd, client_fd, err = 0;
	struct mptcpify *mptcpify_skel;

	mptcpify_skel = mptcpify__open_and_load();
	if (!ASSERT_OK_PTR(mptcpify_skel, "skel_open_load"))
		return libbpf_get_error(mptcpify_skel);

	mptcpify_skel->bss->pid = getpid();

	err = mptcpify__attach(mptcpify_skel);
	if (!ASSERT_OK(err, "skel_attach"))
		goto out;

	/* without MPTCP */
	server_fd = start_server(AF_INET, SOCK_STREAM, NULL, 0, 0);
	if (!ASSERT_GE(server_fd, 0, "start_server")) {
		err = -EIO;
		goto out;
	}

	client_fd = connect_to_fd(server_fd, 0);
	if (!ASSERT_GE(client_fd, 0, "connect to fd")) {
		err = -EIO;
		goto close_server;
	}

	send_byte(client_fd);

	err = verify_mptcpify(server_fd, client_fd);

	close(client_fd);
close_server:
	close(server_fd);
out:
	mptcpify__destroy(mptcpify_skel);
	return err;
}

static void test_mptcpify(void)
{
	struct nstoken *nstoken = NULL;
	int cgroup_fd;

	cgroup_fd = test__join_cgroup("/mptcpify");
	if (!ASSERT_GE(cgroup_fd, 0, "test__join_cgroup"))
		return;

	nstoken = create_netns();
	if (!ASSERT_OK_PTR(nstoken, "create_netns"))
		goto fail;

	ASSERT_OK(run_mptcpify(cgroup_fd), "run_mptcpify");

fail:
	cleanup_netns(nstoken);
	close(cgroup_fd);
}

static int endpoint_init(char *flags)
{
	SYS(fail, "ip -net %s link add veth1 type veth peer name veth2", NS_TEST);
	SYS(fail, "ip -net %s addr add %s/24 dev veth1", NS_TEST, ADDR_1);
	SYS(fail, "ip -net %s link set dev veth1 up", NS_TEST);
	SYS(fail, "ip -net %s addr add %s/24 dev veth2", NS_TEST, ADDR_2);
	SYS(fail, "ip -net %s link set dev veth2 up", NS_TEST);
	SYS(fail, "ip -net %s mptcp endpoint add %s %s", NS_TEST, ADDR_2, flags);

	return 0;
fail:
	return -1;
}

static int _ss_search(char *src, char *dst, char *port, char *keyword)
{
	char cmd[128];
	int n;

	n = snprintf(cmd, sizeof(cmd),
		     "ip netns exec %s ss -Menita src %s dst %s %s %d | grep -q '%s'",
		     NS_TEST, src, dst, port, PORT_1, keyword);
	if (n < 0 || n >= sizeof(cmd))
		return -1;

	return system(cmd);
}

static int ss_search(char *src, char *keyword)
{
	return _ss_search(src, ADDR_1, "dport", keyword);
}

static void run_subflow(char *new)
{
	int server_fd, client_fd, err;
	char cc[TCP_CA_NAME_MAX];
	socklen_t len = sizeof(cc);

	server_fd = start_mptcp_server(AF_INET, ADDR_1, PORT_1, 0);
	if (!ASSERT_GE(server_fd, 0, "start_mptcp_server"))
		return;

	client_fd = connect_to_fd(server_fd, 0);
	if (!ASSERT_GE(client_fd, 0, "connect to fd"))
		goto fail;

	err = getsockopt(server_fd, SOL_TCP, TCP_CONGESTION, cc, &len);
	if (!ASSERT_OK(err, "getsockopt(srv_fd, TCP_CONGESTION)"))
		goto fail;

	send_byte(client_fd);

	ASSERT_OK(ss_search(ADDR_1, "fwmark:0x1"), "ss_search fwmark:0x1");
	ASSERT_OK(ss_search(ADDR_2, "fwmark:0x2"), "ss_search fwmark:0x2");
	ASSERT_OK(ss_search(ADDR_1, new), "ss_search new cc");
	ASSERT_OK(ss_search(ADDR_2, cc), "ss_search default cc");

	close(client_fd);
fail:
	close(server_fd);
}

static void test_subflow(void)
{
	int cgroup_fd, prog_fd, err;
	struct mptcp_subflow *skel;
	struct nstoken *nstoken;

	cgroup_fd = test__join_cgroup("/mptcp_subflow");
	if (!ASSERT_GE(cgroup_fd, 0, "join_cgroup: mptcp_subflow"))
		return;

	skel = mptcp_subflow__open_and_load();
	if (!ASSERT_OK_PTR(skel, "skel_open_load: mptcp_subflow"))
		goto close_cgroup;

	err = mptcp_subflow__attach(skel);
	if (!ASSERT_OK(err, "skel_attach: mptcp_subflow"))
		goto skel_destroy;

	prog_fd = bpf_program__fd(skel->progs.mptcp_subflow);
	err = bpf_prog_attach(prog_fd, cgroup_fd, BPF_CGROUP_SOCK_OPS, 0);
	if (!ASSERT_OK(err, "prog_attach"))
		goto skel_destroy;

	nstoken = create_netns();
	if (!ASSERT_OK_PTR(nstoken, "create_netns: mptcp_subflow"))
		goto skel_destroy;

	if (!ASSERT_OK(endpoint_init("subflow"), "endpoint_init"))
		goto close_netns;

	run_subflow(skel->data->cc);

close_netns:
	cleanup_netns(nstoken);
skel_destroy:
	mptcp_subflow__destroy(skel);
close_cgroup:
	close(cgroup_fd);
}

static void *server(void *arg)
{
	int lfd = (int)(long)arg, err = 0, fd;
	ssize_t nr_sent = 0, bytes = 0;
	char batch[1500];

	fd = accept(lfd, NULL, NULL);
	while (fd == -1) {
		if (errno == EINTR)
			continue;
		err = -errno;
		goto done;
	}

	if (settimeo(fd, 0)) {
		err = -errno;
		goto done;
	}

	while (bytes < total_bytes && !READ_ONCE(stop)) {
		nr_sent = send(fd, &batch,
			       MIN(total_bytes - bytes, sizeof(batch)), 0);
		if (nr_sent == -1 && errno == EINTR)
			continue;
		if (nr_sent == -1) {
			err = -errno;
			break;
		}
		bytes += nr_sent;
	}

	CHECK(bytes != total_bytes, "send", "%zd != %u nr_sent:%zd errno:%d\n",
	      bytes, total_bytes, nr_sent, errno);

done:
	if (fd >= 0)
		close(fd);
	if (err) {
		WRITE_ONCE(stop, 1);
		return ERR_PTR(err);
	}
	return NULL;
}

static void send_data(int lfd, int fd, char *msg)
{
	ssize_t nr_recv = 0, bytes = 0;
	pthread_t srv_thread;
	void *thread_ret;
	char batch[1500];
	int err;

	WRITE_ONCE(stop, 0);

	err = pthread_create(&srv_thread, NULL, server, (void *)(long)lfd);
	if (CHECK(err != 0, "pthread_create", "err:%d errno:%d\n", err, errno))
		return;

	/* recv total_bytes */
	while (bytes < total_bytes && !READ_ONCE(stop)) {
		nr_recv = recv(fd, &batch,
			       MIN(total_bytes - bytes, sizeof(batch)), 0);
		if (nr_recv == -1 && errno == EINTR)
			continue;
		if (nr_recv == -1)
			break;
		bytes += nr_recv;
	}

	CHECK(bytes != total_bytes, "recv", "%zd != %u nr_recv:%zd errno:%d\n",
	      bytes, total_bytes, nr_recv, errno);

	WRITE_ONCE(stop, 1);

	pthread_join(srv_thread, &thread_ret);
	CHECK(IS_ERR(thread_ret), "pthread_join", "thread_ret:%ld",
	      PTR_ERR(thread_ret));
}

static struct nstoken *sched_init(char *flags, char *sched)
{
	struct nstoken *nstoken;

	nstoken = create_netns();
	if (!ASSERT_OK_PTR(nstoken, "create_netns"))
		return NULL;

	if (!ASSERT_OK(endpoint_init("subflow"), "endpoint_init"))
		goto fail;

	SYS(fail, "ip netns exec %s sysctl -qw net.mptcp.scheduler=%s", NS_TEST, sched);

	return nstoken;
fail:
	cleanup_netns(nstoken);
	return NULL;
}

static int has_bytes_sent(char *dst)
{
	return _ss_search(ADDR_1, dst, "sport", "bytes_sent:");
}

static void send_data_and_verify(char *sched, bool addr1, bool addr2)
{
	struct timespec start, end;
	int server_fd, client_fd;
	unsigned int delta_ms;

	server_fd = start_mptcp_server(AF_INET, ADDR_1, PORT_1, 0);
	if (CHECK(server_fd < 0, sched, "start_mptcp_server: %d\n", errno))
		return;

	client_fd = connect_to_fd(server_fd, 0);
	if (CHECK(client_fd < 0, sched, "connect_to_fd: %d\n", errno))
		goto fail;

	if (clock_gettime(CLOCK_MONOTONIC, &start) < 0)
		goto fail;

	send_data(server_fd, client_fd, sched);

	if (clock_gettime(CLOCK_MONOTONIC, &end) < 0)
		goto fail;

	delta_ms = (end.tv_sec - start.tv_sec) * 1000 + (end.tv_nsec - start.tv_nsec) / 1000000;
	printf("%s: %u ms\n", sched, delta_ms);

	if (addr1)
		CHECK(has_bytes_sent(ADDR_1), sched, "should have bytes_sent on addr1\n");
	else
		CHECK(!has_bytes_sent(ADDR_1), sched, "shouldn't have bytes_sent on addr1\n");
	if (addr2)
		CHECK(has_bytes_sent(ADDR_2), sched, "should have bytes_sent on addr2\n");
	else
		CHECK(!has_bytes_sent(ADDR_2), sched, "shouldn't have bytes_sent on addr2\n");

	close(client_fd);
fail:
	close(server_fd);
}

static void test_default(void)
{
	struct nstoken *nstoken;

	nstoken = sched_init("subflow", "default");
	if (!ASSERT_OK_PTR(nstoken, "sched_init:default"))
		goto fail;

	send_data_and_verify("default", WITH_DATA, WITH_DATA);

fail:
	cleanup_netns(nstoken);
}

static void test_bpf_sched(struct bpf_object *obj, char *sched,
			   bool addr1, bool addr2)
{
	char bpf_sched[MPTCP_SCHED_NAME_MAX] = "bpf_";
	struct nstoken *nstoken;
	struct bpf_link *link;
	struct bpf_map *map;

	if (!ASSERT_LT(strlen(bpf_sched) + strlen(sched),
		       MPTCP_SCHED_NAME_MAX, "Scheduler name too long"))
		return;

	map = bpf_object__find_map_by_name(obj, sched);
	link = bpf_map__attach_struct_ops(map);
	if (CHECK(!link, sched, "attach_struct_ops: %d\n", errno))
		return;

	nstoken = sched_init("subflow", strcat(bpf_sched, sched));
	if (CHECK(!nstoken, sched, "sched_init: %d\n", errno))
		goto fail;

	send_data_and_verify(sched, addr1, addr2);

fail:
	cleanup_netns(nstoken);
	bpf_link__destroy(link);
}

#define MPTCP_SCHED_TEST(sched, addr1, addr2)			\
static void test_##sched(void)					\
{								\
	struct mptcp_bpf_##sched *skel;				\
								\
	skel = mptcp_bpf_##sched##__open_and_load();		\
	if (!ASSERT_OK_PTR(skel, "open_and_load:" #sched))	\
		return;						\
								\
	test_bpf_sched(skel->obj, #sched, addr1, addr2);	\
	mptcp_bpf_##sched##__destroy(skel);			\
}

MPTCP_SCHED_TEST(first, WITH_DATA, WITHOUT_DATA);
MPTCP_SCHED_TEST(bkup, WITH_DATA, WITHOUT_DATA);
MPTCP_SCHED_TEST(rr, WITH_DATA, WITH_DATA);
MPTCP_SCHED_TEST(red, WITH_DATA, WITH_DATA);
MPTCP_SCHED_TEST(burst, WITH_DATA, WITH_DATA);

#define RUN_MPTCP_TEST(suffix)					\
do {								\
	if (test__start_subtest(#suffix))			\
		test_##suffix();				\
} while (0)

void test_mptcp(void)
{
	RUN_MPTCP_TEST(base);
	RUN_MPTCP_TEST(mptcpify);
	RUN_MPTCP_TEST(subflow);
	RUN_MPTCP_TEST(default);
	RUN_MPTCP_TEST(first);
	RUN_MPTCP_TEST(bkup);
	RUN_MPTCP_TEST(rr);
	RUN_MPTCP_TEST(red);
	RUN_MPTCP_TEST(burst);
}
