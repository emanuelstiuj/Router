# ROUTER DATA PLANE

## Router Initialization and Configuration:
- Initializing the routing and ARP tables.  
- The ARP table will be dynamically populated during program execution.  
- Creating a trie for routing table lookup.  

## Packet Reception:
- Waiting for and receiving packets from any available network interface.  

## Packet Type Verification:
- If the packet is of type **IP**:  
  - Checking the correctness of the IP header checksum.  
  - If the TTL expires, sending an **ICMP timeout**.  
  - If no route is available, sending an **ICMP host unreachable**.  
  - If the packet is an **ICMP Echo Request** and the router is the destination, sending an **ICMP Echo Reply**.  
- If the packet is of type **ARP**:  
  - If it is an **ARP Request** directed to the router, it sends an **ARP Reply**.  
  - If it is an **ARP Reply** destined for the router, the sender's MAC address is added to the ARP table, and queued packets are checked for transmission.  

## IP Packet Forwarding:
- Finding the best route for the packet's destination IP.  
- Decreasing the TTL and updating the IP header checksum.  
- Looking up the next-hop MAC address in the ARP table.  
- If the next-hop MAC address is known, the packet is sent through the corresponding interface.  
- If the MAC address is unknown, an **ARP Request** is sent to retrieve it.  
- Packets that cannot be sent immediately (due to a missing MAC address) are queued.  

This is the main flow of the router, dynamically deciding how to handle each received packet based on information from the routing and ARP tables.  

---

## Trie Creation  

The function `create_trie()` receives the routing table and its length as parameters and builds a trie corresponding to the table entries.  

For each entry in the routing table:  
- The prefix and mask are extracted.  
- The mask length is determined.  
- The prefix is traversed **bit by bit**, creating or accessing corresponding nodes in the trie.  
- When the end of the prefix is reached, the corresponding node is marked as having a route and stores information such as the next hop and the interface for forwarding the packet.  

---

## Finding the Best Route  

The function `get_best_route_trie()` receives a destination IP address and the trie associated with the routing table.  

For each bit in the destination IP address:  
- It checks if there is a corresponding node.  
- If a node exists and has an associated route, the best-found route is updated.
