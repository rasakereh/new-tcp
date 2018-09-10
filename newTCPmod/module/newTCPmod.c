#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/tcp.h>
#include <net/tcp.h>
#include <net/inet_connection_sock.h>
#include <uapi/linux/tcp.h>
#include <uapi/linux/snmp.h>
#include <net/sock.h>
#include <net/ip.h>

//functions to be override
extern void (*tcp_rcv_established_aux)(struct sock *, struct sk_buff *,
		const struct tcphdr *);

/* function in use */
//tcp_sk;
//tcp_mstamp_refresh;
//inet_csk;
//tcp_flag_word;
//TCP_SKB_CB;
//after;
//TCPOLEN_TSTAMP_ALIGNED;
//__kfree_skb;
//tcp_data_snd_check;
//TCP_INC_STATS;
//TCP_MIB_INERRS;
//tcp_checksum_complete;
//tcp_rcv_rtt_measure_ts;
//sock_net;
//LINUX_MIB_TCPHPHITS;
//NET_INC_STATS;
//inet_csk_ack_scheduled;
//kfree_skb_partial;

/*
 * Functions and macros below are not in headers (Ey Khodaaaaaaaaa!)
 * so I decided to rewrite(copy/paste?) some and export the rest
 * The source can be find in:
 * linux-hwe-$(version)/net/ipv4/tcp_input.c 
 */
//tcp_data_snd_check
extern inline void tcp_data_snd_check(struct sock *sk);
//tcp_rcv_rtt_measure_ts
extern inline void tcp_rcv_rtt_measure_ts(struct sock *sk,
					  const struct sk_buff *skb);
//tcp_parse_aligned_timestamp;
extern bool tcp_parse_aligned_timestamp(struct tcp_sock *tp,
			const struct tcphdr *th);
//tcp_store_ts_recent;
extern void tcp_store_ts_recent(struct tcp_sock *tp);
//tcp_ack;
extern int tcp_ack(struct sock *sk, const struct sk_buff *skb, int flag);
//tcp_validate_incoming;
extern bool tcp_validate_incoming(struct sock *sk, struct sk_buff *skb,
				  const struct tcphdr *th, int syn_inerr);
//Macros
#define TCP_HP_BITS (~(TCP_RESERVED_BITS|TCP_FLAG_PSH))
#define FLAG_DATA		0x01 /* Incoming frame contained data.		*/
#define FLAG_SLOWPATH		0x100 /* Do not skip RFC checks for window update.*/
#define FLAG_UPDATE_TS_RECENT	0x4000 /* tcp_replace_ts_recent() */
//tcp_urg;
extern void tcp_urg(struct sock *sk, struct sk_buff *skb,
			const struct tcphdr *th);
//tcp_data_queue;
extern void tcp_data_queue(struct sock *sk, struct sk_buff *skb);
//tcp_drop;
extern void tcp_drop(struct sock *sk, struct sk_buff *skb);
//tcp_queue_rcv;
extern int __must_check tcp_queue_rcv(struct sock *sk, struct sk_buff *skb,
				int hdrlen, bool *fragstolen);
//__tcp_ack_snd_check;
extern void __tcp_ack_snd_check(struct sock *sk, int ofo_possible);
//tcp_ack_snd_check;
extern inline void tcp_ack_snd_check(struct sock *sk);
//tcp_event_data_recv;
extern void tcp_event_data_recv(struct sock *sk, struct sk_buff *skb);

void (*original_call)(struct sock *, struct sk_buff *,
		const struct tcphdr *);

static void new_tcp_rcv_established(struct sock *sk, struct sk_buff *skb,
		const struct tcphdr *th)
{
	unsigned int len = skb->len;
	struct tcp_sock *tp = tcp_sk(sk);

	tcp_mstamp_refresh(tp);
	if (unlikely(!sk->sk_rx_dst))
		inet_csk(sk)->icsk_af_ops->sk_rx_dst_set(sk, skb);
	/*
	 *	Header prediction.
	 *	The code loosely follows the one in the famous
	 *	"30 instruction TCP receive" Van Jacobson mail.
	 *
	 *	Van's trick is to deposit buffers into socket queue
	 *	on a device interrupt, to call tcp_recv function
	 *	on the receive process context and checksum and copy
	 *	the buffer to user space. smart...
	 *
	 *	Our current scheme is not silly either but we take the
	 *	extra cost of the net_bh soft interrupt processing...
	 *	We do checksum and copy also but from device to kernel.
	 */

	tp->rx_opt.saw_tstamp = 0;

	/*	pred_flags is 0xS?10 << 16 + snd_wnd
	 *	if header_prediction is to be made
	 *	'S' will always be tp->tcp_header_len >> 2
	 *	'?' will be 0 for the fast path, otherwise pred_flags is 0 to
	 *  turn it off	(when there are holes in the receive
	 *	 space for instance)
	 *	PSH flag is ignored.
	 */

	if ((tcp_flag_word(th) & TCP_HP_BITS) == tp->pred_flags &&
	    TCP_SKB_CB(skb)->seq == tp->rcv_nxt &&
	    !after(TCP_SKB_CB(skb)->ack_seq, tp->snd_nxt)
	    ) {
		int tcp_header_len = tp->tcp_header_len;

		/* Timestamp header prediction: tcp_header_len
		 * is automatically equal to th->doff*4 due to pred_flags
		 * match.
		 */

		/* Check timestamp */
		if (tcp_header_len == sizeof(struct tcphdr) + TCPOLEN_TSTAMP_ALIGNED) {
			/* No? Slow path! */
			if (!tcp_parse_aligned_timestamp(tp, th))
				goto slow_path;

			/* If PAWS failed, check it more carefully in slow path */
			if ((s32)(tp->rx_opt.rcv_tsval - tp->rx_opt.ts_recent) < 0)
				goto slow_path;

			/* DO NOT update ts_recent here, if checksum fails
			 * and timestamp was corrupted part, it will result
			 * in a hung connection since we will drop all
			 * future packets due to the PAWS test.
			 */
		}

		if (len <= tcp_header_len) {
			/* Bulk data transfer: sender */
			if (len == tcp_header_len) {
				/* Predicted packet is in window by definition.
				 * seq == rcv_nxt and rcv_wup <= rcv_nxt.
				 * Hence, check seq<=rcv_wup reduces to:
				 */
				if (tcp_header_len ==
				    (sizeof(struct tcphdr) + TCPOLEN_TSTAMP_ALIGNED) &&
				    tp->rcv_nxt == tp->rcv_wup)
					tcp_store_ts_recent(tp);

				/* We know that such packets are checksummed
				 * on entry.
				 */
				tcp_ack(sk, skb, 0);
				__kfree_skb(skb);
				tcp_data_snd_check(sk);
				return;
			} else { /* Header too small */
				TCP_INC_STATS(sock_net(sk), TCP_MIB_INERRS);
				goto discard;
			}
		} else {
			int eaten = 0;
			bool fragstolen = false;

			if (tcp_checksum_complete(skb))
			{
				TCP_INC_STATS(sock_net(sk), TCP_MIB_CSUMERRORS);
				TCP_INC_STATS(sock_net(sk), TCP_MIB_INERRS);
			}

			if ((int)skb->truesize > sk->sk_forward_alloc)
				goto step5;

			/* Predicted packet is in window by definition.
			 * seq == rcv_nxt and rcv_wup <= rcv_nxt.
			 * Hence, check seq<=rcv_wup reduces to:
			 */
			if (tcp_header_len ==
			    (sizeof(struct tcphdr) + TCPOLEN_TSTAMP_ALIGNED) &&
			    tp->rcv_nxt == tp->rcv_wup)
				tcp_store_ts_recent(tp);

			tcp_rcv_rtt_measure_ts(sk, skb);

			NET_INC_STATS(sock_net(sk), LINUX_MIB_TCPHPHITS);

			/* Bulk data transfer: receiver */
			eaten = tcp_queue_rcv(sk, skb, tcp_header_len,
					      &fragstolen);

			tcp_event_data_recv(sk, skb);

			if (TCP_SKB_CB(skb)->ack_seq != tp->snd_una) {
				/* Well, only one small jumplet in fast path... */
				tcp_ack(sk, skb, FLAG_DATA);
				tcp_data_snd_check(sk);
				if (!inet_csk_ack_scheduled(sk))
					goto no_ack;
			}

			__tcp_ack_snd_check(sk, 0);
no_ack:
			if (eaten)
				kfree_skb_partial(skb, fragstolen);
			sk->sk_data_ready(sk);
			return;
		}
	}

slow_path:
	if (len < (th->doff << 2))
		goto csum_error;
	if(tcp_checksum_complete(skb))
	{
		TCP_INC_STATS(sock_net(sk), TCP_MIB_CSUMERRORS);
		TCP_INC_STATS(sock_net(sk), TCP_MIB_INERRS);
	}

	if (!th->ack && !th->rst && !th->syn)
		goto discard;

	/*
	 *	Standard slow path.
	 */

	if (!tcp_validate_incoming(sk, skb, th, 1))
		return;

step5:
	if (tcp_ack(sk, skb, FLAG_SLOWPATH | FLAG_UPDATE_TS_RECENT) < 0)
		goto discard;

	tcp_rcv_rtt_measure_ts(sk, skb);

	/* Process urgent data. */
	tcp_urg(sk, skb, th);

	/* step 7: process the segment text */
	tcp_data_queue(sk, skb);

	tcp_data_snd_check(sk);
	tcp_ack_snd_check(sk);
	return;


csum_error:
	TCP_INC_STATS(sock_net(sk), TCP_MIB_CSUMERRORS);
	TCP_INC_STATS(sock_net(sk), TCP_MIB_INERRS);

discard:
	tcp_drop(sk, skb);
}

int init_module()
{
	printk(KERN_ALERT "STARTED\n");

	original_call = tcp_rcv_established_aux;
	tcp_rcv_established_aux = &new_tcp_rcv_established;

	return 0;
}

void cleanup_module()
{
	tcp_rcv_established_aux = original_call;
	printk(KERN_ALERT "FINISHED\n");
}

MODULE_LICENSE("GPL");

