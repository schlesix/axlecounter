# axlecounter

## What it does
The software shows diffs between two pcap-Files. The focus is on identifying packets that are there at one point of a connection, e. g. in a client subnet, but are missing at another point, e. g. in a server subnet. It looks at the IP Layer (Network Layer) and is able to consider IP packets with an Identification field not properly set (happens e. g. for UDP traffic for telephony).

