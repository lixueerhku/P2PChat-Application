# P2PChat-Application
An instant chat program that supports message exchanges between peers directly.

Run room server:
$./room_server_mac

Run P2PChat python program:
$python3 P2PChat-UI.py <roomserver_address> <roomserver_port> <myport>
e.g. python3 P2PChat-UI.py localhost 32340 60000

Get local IP address
$ifconfig | grep "inet " | grep -v 127.0.0.1

A demo vedio:
https://www.youtube.com/watch?v=8aR6yXUFSok

