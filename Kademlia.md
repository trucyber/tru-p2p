# Kademlia
---

## NodeIDs
* Each node on a network is a leaf on a binary tree.
* Each node has a 160-bit NodeID (SHA-1) and its  
position is determined by the shortest unique  
prefix of its ID.
* To find the distance between two nodes we XOR  
the two IDs.
* From the perspective of a node, the tree is  
divided into subtrees where tje 160th subtree  
contains the individual node.
* It is ensured that each node at least knows of  
one node on each of its subtrees. This guarentees  
that a node can locate any node by its ID.
---

## Routing Tables
* Is a binary tree whose leaves are k-buckets.  
Routing tables maintain detailed knowledge of the  
address space closest to them, and less knowledge  
of the more distand address space.
* Symmetry is useful since it means that the closer  
nodes will maintain knowledge of simillar parts of the  
subtree vs a remote part.
* **K-Bucket** is a list of routing addresses of other  
nodes in the network, which are maintained by each node
and contain the IP address, portm and NodeID for peer  
participants in the system. Longest-lived nodes are  
preferred. This means that a node's routing state can  
not be overtaken by flooding the system with new nodes.
* Routing table size is asymptotically bounded by  
>> O(log<sub>2</sub>(n/k))
where _n_ is the actual number of nodes in the network  
and _k_ is the size of the bucket. Larger bucket  
implementations slightly reduce the number of buckets  
in the routing table.
---

## Inter-Peer Messaging
* All peers must speak the same language.
* Consists of 4 Remote Procedure Calls:
    1. **PING**
    2. **STORE**: Instructs node to store a key-value pair
    3. **FIND_NODE**: returns info about the _k_ nodes  
    closest to the target ID
    4. **FIND_VALUE**: Similar to FIND_NODE RPC but if the  
    the recipient has received a STORE for the given key, it  
    just returns the stored value  