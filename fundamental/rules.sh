# set up the default gateway, which will be used for filling the
# destination MAC address, i.e source MAC address will be device
# MAC address, but for remote servers the destination MAC will
# be filled with default gateway's MAC address and its the job of
# default gateway to transfer the packet to destination
ip route add table 100 default dev eth1 via 192.168.0.1
ip route add table 101 default dev eth2 via 192.168.29.1
# select table based on mark on the packet
ip rule add fwmark 100 table 100
ip rule add fwmark 101 table 101
# for locally initiated connections
ip rule add from 192.168.29.2 table 100
ip rule add from 192.168.0.109 table 101
# other configs
echo 1 >/proc/sys/net/ipv4/ip_forward
echo 0 >/proc/sys/net/ipv4/conf/all/rp_filter

# eth1 — WAN connection 1, IP 192.168.0.109 default gw 192.168.0.1
# eth2 — WAN connection 2, IP 192.168.29.2 default gw 192.168.29.1
# eth0 — LAN connection, IP 172.17.0.1
