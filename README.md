# ARP-Poison-Subnet
A tool to discover and ARP poison targets on local network.
The tool has 2 commands F,A
F - Find targets
  send MDNS queries to computers on network inorder to discover their names
A - Attack target
  poisons targets ARP cache with "I am default gateway" and replies to the first HTTP GET request with a html file saying "you got hacked".
