#include "queue.h"
#include "lib.h"
#include "protocols.h"
#include <arpa/inet.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

// Routing table and its size
struct route_table_entry *routing_table;
int routing_table_len;

// ARP table and its size
struct arp_table_entry *arp_table;
int arp_table_len;

// Function that returns the arp entry corresponding to the IP
struct arp_table_entry *get_arp_table_entry(uint32_t ip) {
    struct arp_table_entry *aux;
    for (int i = 0; i < arp_table_len; i++) {
        aux = &arp_table[i];
        if (aux->ip == ip) {
            return aux;
        }
    }
    return NULL;
}

// Function that finds the best route efficiently, using binary search
// (based on the fact that the table is sorted)
void binary_search_route(uint32_t ip, int left, int right, struct route_table_entry **found) {
    if (left > right) {
        return ;    // Invalid search range
    }

    int middle = (left + right) / 2;
    uint32_t prefix = ntohl(routing_table[middle].prefix & routing_table[middle].mask);
    uint32_t given_prefix = ntohl(ip & routing_table[middle].mask);

    if (prefix == given_prefix) {
        *found = &routing_table[middle];    // Match => update the found route pointer
        binary_search_route(ip, middle + 1, right, found);
    }
    else if (prefix > given_prefix) {
        binary_search_route(ip, left, middle - 1, found);   // Search first half
    }
    else {
        binary_search_route(ip, middle + 1, right, found);  // Search second half
    }
}

// Auxiliary function for qsort (sorting by prefixes and mask)
int compare_func(const void* x, const void* y) {
	struct route_table_entry *x_route = (struct route_table_entry *)x;
	struct route_table_entry *y_route = (struct route_table_entry *)y;
    uint32_t prefix_x = ntohl(x_route->prefix & x_route->mask);
    uint32_t prefix_y = ntohl(y_route->prefix & y_route->mask);
    uint32_t mask_x = ntohl(x_route->mask);
    uint32_t mask_y = ntohl(y_route->mask);

    if (prefix_x == prefix_y)
        return mask_x - mask_y;
    else
        return prefix_x - prefix_y;
}

// Function for icmp routing process
void icmp_protocol(int interface, struct ether_header *eth_hdr, struct iphdr *ip_hdr, int type, int code) {
    char buf[MAX_PACKET_LEN];
    char err_case[MAX_PACKET_LEN];

    // Iinitialization for new eth header
	struct ether_header *new_eth_hdr = calloc(1, sizeof(struct ether_header));
    memmove(new_eth_hdr->ether_shost, eth_hdr->ether_dhost, 6);
	memmove(new_eth_hdr->ether_dhost, eth_hdr->ether_shost, 6);
    new_eth_hdr->ether_type = htons(0x0800);
	// Iinitialization for new ip header
    struct iphdr *new_ip_hdr = calloc(1, sizeof(struct iphdr)); // Ignored fields are set to 0
	new_ip_hdr->ihl = ip_hdr->ihl;
    new_ip_hdr->version = ip_hdr->version;
    new_ip_hdr->tot_len = htons(sizeof(struct iphdr) + sizeof(struct icmphdr));
	new_ip_hdr->ttl = 64;
	new_ip_hdr->protocol = 0x1;
    new_ip_hdr->daddr = ip_hdr->saddr;
	new_ip_hdr->saddr = ip_hdr->daddr;
	new_ip_hdr->check = checksum((uint16_t *)new_ip_hdr, sizeof(struct iphdr));
	// Iinitialization for new icmp header
    struct icmphdr *new_icmp_hdr = calloc(1, sizeof(struct icmphdr));   // Ignored fields are set to 0
	new_icmp_hdr->type = type;
	new_icmp_hdr->code = code;
	new_icmp_hdr->checksum = checksum((uint16_t *)new_icmp_hdr, sizeof(struct icmphdr));
    // Add new headers to buffer
	memmove(buf, new_eth_hdr, sizeof(struct ether_header));
	memmove(sizeof(struct ether_header) + buf, new_ip_hdr, sizeof(struct iphdr));
	memmove(sizeof(struct ether_header) + sizeof(struct iphdr) + buf, new_icmp_hdr, sizeof(struct icmphdr));
    // Include payload from the original packet, case 3 & 11 types
	if (new_icmp_hdr->type) {
        memmove(err_case, ip_hdr, 2 * sizeof(struct iphdr) + sizeof(struct icmphdr));
		memmove(sizeof(struct iphdr) + err_case, buf, 8);
        memmove(sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct icmphdr) + buf, err_case, 2 * sizeof(struct iphdr) + sizeof(struct icmphdr));
	}
    send_to_link(interface, buf, 2 * sizeof(struct iphdr) + sizeof(struct icmphdr) + sizeof(struct ether_header));
    free(new_eth_hdr);
    free(new_ip_hdr);
    free(new_icmp_hdr);
}

int main(int argc, char *argv[]) {
    char buf[MAX_PACKET_LEN];

    // Do not modify this line
    init(argc - 2, argv + 2);

    // Allocating memory for the routing table and reading it
    routing_table = malloc(sizeof(struct route_table_entry) * 80000);
    DIE(!routing_table, "allocation error");
    routing_table_len = read_rtable(argv[1], routing_table);
    // Sorting the routing table for the binary search
    qsort(routing_table, routing_table_len, sizeof(struct route_table_entry), compare_func); 
    
    // Allocating memory for the ARP table and reading it
    arp_table = malloc(sizeof(struct arp_table_entry) * 100);
    DIE(!arp_table, "allocation error");
    arp_table_len = parse_arp_table("arp_table.txt", arp_table);
	

    while (1) {
        int interface;
        size_t len;

        interface = recv_from_any_link(buf, &len);
        DIE(interface < 0, "recv_from_any_links");

        struct ether_header *eth_hdr = (struct ether_header *)buf;
        /* Note that packets received are in network order,
		any header field which has more than 1 byte will need to be conerted to
		host order. For example, ntohs(eth_hdr->ether_type). The oposite is needed when
		sending a packet on the link, */

        // Checking if the packet is IPv4
        if (eth_hdr->ether_type == ntohs(0x0800)) { // IPv4
            
            struct iphdr *ip_hdr = (struct iphdr *)(sizeof(struct ether_header) + buf);
            int icmp, type, code;   // Variables for ICMP_protocol
            icmp = type = code = 0;

            // Checking the destination
            uint32_t dest = inet_addr(get_interface_ip(interface));
            if (ip_hdr->daddr == dest) {
                // Reached destination, update variables for protocol
                icmp = 1;
                type = 0;
                code = 0;
            }

            // Verifying TTL
            if (ip_hdr->ttl <= 1 && !icmp) {
                // Expired TTL => Time exceeded, update variables for protocol
                icmp = 1;
                type = 11;
                code = 0;
            }
            
            // Checking the best route
            struct route_table_entry *route = NULL;
            binary_search_route(ip_hdr->daddr, 0, routing_table_len - 1, &route);
            if (!route && !icmp) {
                // No route => Destination unreachable, update variables for protocol
                icmp = 1;
                type = 3;
                code = 0;
            }

            if (icmp) {
                icmp_protocol(interface, eth_hdr, ip_hdr, type, code);
                continue;
            }

            // Verifying the checksum
            if (checksum((uint16_t *)ip_hdr, sizeof(struct iphdr))) {
                // Bad checksum => ignore
                continue;
            }

            // Checksum recalculation
            ip_hdr->check = 0;
            ip_hdr->ttl--;
            uint16_t update_checksum = htons(checksum((uint16_t *)ip_hdr, sizeof(struct iphdr)));
            ip_hdr->check = update_checksum;

            // ARP table entry for the next hop
            struct arp_table_entry *arp_table_entry = get_arp_table_entry(route->next_hop);
            if (!arp_table_entry) {
                // entry not found
                continue;
            }

            // Updating Ethernet header
            memmove(eth_hdr->ether_dhost, arp_table_entry->mac, 6);
            
            get_interface_mac(route->interface, eth_hdr->ether_shost);
            send_to_link(route->interface, buf, len);
        }
    }

    free(routing_table);
    free(arp_table);
    return 0;

}