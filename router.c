#include <arpa/inet.h>
#include <string.h>
#include "queue.h"
#include "lib.h"
#include "protocols.h"

void send_icmp(struct iphdr *original_ip_hdr, struct ether_header *original_eth_hdr, uint8_t type, uint8_t code, int interface)
{
	char *packet = malloc(sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct icmphdr) + sizeof(struct iphdr) + 8);
	struct ether_header *eth_hdr_packet = (struct ether_header *) packet;
	struct iphdr *ip_hdr_packet = (struct iphdr *) (packet + sizeof(struct ether_header));
	struct icmphdr *icmp_hdr_packet = (struct icmphdr *) ((char *) ip_hdr_packet + sizeof(struct iphdr));

	// the ethernet header of the final packet
	memcpy(eth_hdr_packet->ether_dhost, original_eth_hdr->ether_shost, 6);
	get_interface_mac(interface, eth_hdr_packet->ether_shost);
	eth_hdr_packet->ether_type = htons(ETHERTYPE_IP);

	// the ip header of the final packet
	ip_hdr_packet->daddr = original_ip_hdr->saddr;
	ip_hdr_packet->saddr = inet_addr(get_interface_ip(interface));
	ip_hdr_packet->frag_off = 0;
	ip_hdr_packet->id = original_ip_hdr->id;
	ip_hdr_packet->ihl = 5;
	ip_hdr_packet->protocol = 1;
	ip_hdr_packet->frag_off = 0;
	ip_hdr_packet->tos = 0;
	ip_hdr_packet->version = 4;
	ip_hdr_packet->ttl = 64;
	ip_hdr_packet->check = 0;
	ip_hdr_packet->tot_len = htons(sizeof(struct iphdr) + sizeof(struct icmphdr) + sizeof(struct iphdr) + 8);
	ip_hdr_packet->check = htons(checksum((uint16_t *) ip_hdr_packet, sizeof(struct iphdr)));

	// the icmp header of the final packet
	icmp_hdr_packet->type = type;
	icmp_hdr_packet->code = code;
	icmp_hdr_packet->un.echo.id = original_ip_hdr->id;
	icmp_hdr_packet->un.echo.sequence = 0;
	icmp_hdr_packet->checksum = 0;

	// the original ip header + 64 bits of data
	memcpy(((char *) icmp_hdr_packet + sizeof(struct icmphdr)), original_ip_hdr, sizeof(struct iphdr) + 8);

	icmp_hdr_packet->checksum = htons(checksum((uint16_t *) icmp_hdr_packet, sizeof(struct icmphdr) + sizeof(struct iphdr) + 8));

	send_to_link(interface, packet, sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct icmphdr) + sizeof(struct iphdr) + 8);

	free(packet);
}

int main(int argc, char *argv[])
{
	char buf[MAX_PACKET_LEN];

	// Do not modify this line
	init(argc - 2, argv + 2);

	struct route_table_entry *rtable = malloc(sizeof(struct route_table_entry) * 100000);
	int rtable_len = read_rtable(argv[1], rtable);

	struct trie *trie = create_trie(rtable, rtable_len);
	free(rtable);

	struct arp_table_entry *arp_table = malloc(sizeof(struct arp_table_entry) * 10);
	int arp_table_len = 0;

	queue queue_packets = queue_create();
	int queue_len = 0;

	unsigned char broadcast_mac[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
	unsigned char null_mac[6] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

	while (1) {

		int interface;
		size_t len;

		interface = recv_from_any_link(buf, &len);
		DIE(interface < 0, "recv_from_any_links");

		struct ether_header *eth_hdr = (struct ether_header *) buf;
		uint8_t mac_router[6];
		get_interface_mac(interface, mac_router);

		// L2 validation
		if (strncmp((char *)eth_hdr->ether_dhost, (char *)mac_router, 6) != 0 &&
				strncmp((char *)eth_hdr->ether_dhost, (char *)broadcast_mac, 6) != 0)
			continue;

		if (eth_hdr->ether_type == ntohs(ETHERTYPE_IP)) {
			struct iphdr *ip_hdr = (struct iphdr *) (buf + (sizeof(struct ether_header)));

			// wrong checksum
			if (checksum((uint16_t *) ip_hdr, sizeof(struct iphdr)) != 0)
				continue;

			// ttl expired
			if (ip_hdr->ttl <= 1) {
				send_icmp(ip_hdr, eth_hdr, 11, 0, interface);
				continue;
			}

			if (ip_hdr->daddr == inet_addr(get_interface_ip(interface)) && ip_hdr->protocol == 1) {
				struct icmphdr *icmp_hdr = (struct icmphdr *) ((char *) ip_hdr + sizeof(struct iphdr));

				// the router received an echo request
				if (icmp_hdr->type == 8 && icmp_hdr->code == 0)
					send_icmp(ip_hdr, eth_hdr, 0, 0, interface);

				continue;
			}

			struct trie *node = get_best_route_trie(ip_hdr->daddr, trie);

			// host unreachable
			if (node == NULL) {
				send_icmp(ip_hdr, eth_hdr, 3, 0, interface);
				continue;
			}

			ip_hdr->ttl--;
			ip_hdr->check = 0;
			ip_hdr->check = htons(checksum((uint16_t *) ip_hdr, sizeof(struct iphdr)));

			struct arp_table_entry *next_hop_mac = get_mac_entry(node->next_hop, arp_table, arp_table_len);

			if (next_hop_mac == NULL) {
				// the MAC is not found in the arp_table
				// enqueue the packet and its length
				char *packet = malloc(len);
				memcpy(packet, buf, len);

				struct node_queue *node_que = malloc(sizeof(struct node_queue));
				node_que->packet = packet;
				node_que->len = len;

				queue_enq(queue_packets, node_que);
				queue_len++;

				// an arp_request is going to be sent
				char *arp_req_packet = malloc(sizeof(struct ether_header) + sizeof(struct arp_header));
				struct ether_header* arp_eth_hdr = (struct ether_header *) arp_req_packet;
				struct arp_header *arp_hdr = (struct arp_header *) (arp_req_packet + (sizeof(struct ether_header)));

				// the ethernet header of the arp request
				memcpy(arp_eth_hdr->ether_dhost, broadcast_mac, 6);						
				get_interface_mac(node->interface, arp_eth_hdr->ether_shost);
				arp_eth_hdr->ether_type = htons(ETHERTYPE_ARP);

				// the arp header of the arp request
				arp_hdr->htype = htons(1);
				arp_hdr->ptype = htons(ETHERTYPE_IP);
				arp_hdr->hlen = 6;
				arp_hdr->plen = 4;
				arp_hdr->op = htons(1);
				memcpy(arp_hdr->sha, arp_eth_hdr->ether_shost, 6);
				memcpy(arp_hdr->tha, null_mac, 6);
				arp_hdr->tpa = node->next_hop;
				arp_hdr->spa = inet_addr(get_interface_ip(node->interface));

				send_to_link(node->interface, arp_req_packet, sizeof(struct ether_header) + sizeof(struct arp_header));
				free(arp_req_packet);

				continue;
			}

			// the MAC destination was found in the arp table
			memcpy(eth_hdr->ether_dhost, next_hop_mac->mac, sizeof(eth_hdr->ether_dhost));
			get_interface_mac(node->interface, eth_hdr->ether_shost);

			send_to_link(node->interface, buf, len);

		} else if (eth_hdr->ether_type == ntohs(ETHERTYPE_ARP)) {
			struct arp_header *arp_hdr = (struct arp_header *) (buf + sizeof(struct ether_header));

			// the router recieved an arp request
			if (ntohs(arp_hdr->op) == 1) {
				// the router is the destination
				if (arp_hdr->tpa == inet_addr(get_interface_ip(interface))) {

					// an arp reply is going to be sent
					char *arp_reply_packet = malloc(sizeof(struct ether_header) + sizeof(struct arp_header));
					struct ether_header *arp_eth_hdr = (struct ether_header *) arp_reply_packet;
					struct arp_header *arp_hdr_reply = (struct arp_header *) (arp_reply_packet + (sizeof(struct ether_header)));

					// the ethernet header of the arp reply
					memcpy(arp_eth_hdr->ether_dhost, eth_hdr->ether_shost, 6);
					get_interface_mac(interface, arp_eth_hdr->ether_shost);
					arp_eth_hdr->ether_type = htons(ETHERTYPE_ARP);

					// the arp header of the arp reply
					arp_hdr_reply->htype = htons(1);
					arp_hdr_reply->ptype = htons(ETHERTYPE_IP);
					arp_hdr_reply->hlen = 6;
					arp_hdr_reply->plen = 4;
					arp_hdr_reply->op = htons(2);
					memcpy(arp_hdr_reply->tha, arp_eth_hdr->ether_dhost, 6);
					get_interface_mac(interface, arp_hdr_reply->sha);
					arp_hdr_reply->tpa = arp_hdr->spa;
					arp_hdr_reply->spa = inet_addr(get_interface_ip(interface));

					send_to_link(interface, arp_reply_packet, sizeof(struct ether_header) + sizeof(struct arp_header));
					free(arp_reply_packet);
				} 
			} else if (ntohs(arp_hdr->op) == 2) {
				// the router received an arp reply

				if (get_mac_entry(arp_hdr->spa, arp_table, arp_table_len) == NULL) {
					// a new entry is added in the arp table
					struct arp_table_entry new_entry;

					new_entry.ip = arp_hdr->spa;
					memcpy(new_entry.mac, arp_hdr->sha, 6);
					arp_table[arp_table_len] = new_entry;
					arp_table_len++;
				}

				if (arp_hdr->tpa == inet_addr(get_interface_ip(interface))) {
					// the router is the destination
					int queue_len_aux = queue_len;
					int sent = 0;
					
					// all the packets saved in the queue are going to be sent if the MAC destination is known
					while (queue_len_aux) {
						struct node_queue *node_que = (struct node_queue *) queue_deq(queue_packets);
						char *packet = node_que->packet;

						struct ether_header *eth_hdr = (struct ether_header *) packet;
						struct iphdr *ip_hdr = (struct iphdr *) (packet + (sizeof(struct ether_header)));
						struct trie *node = get_best_route_trie(ip_hdr->daddr, trie);

						struct arp_table_entry *next_hop_mac = get_mac_entry(node->next_hop, arp_table, arp_table_len);

						if (next_hop_mac == NULL) {
							queue_enq(queue_packets, node_que);
							queue_len_aux--;
							continue;
						}

						memcpy(eth_hdr->ether_dhost, next_hop_mac->mac, 6);
						get_interface_mac(node->interface, eth_hdr->ether_shost);

						send_to_link(node->interface, packet, node_que->len);
						free(packet);
						free(node_que);
						queue_len_aux--;
						sent++;
					}

					queue_len -= sent;
				}
			}
		}
	}
}

