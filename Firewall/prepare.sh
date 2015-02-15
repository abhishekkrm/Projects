echo "GATEWAY MAC"
arp -a
echo "INTERNAL INTF INFO"
sudo ip netns exec ep1 ifconfig -a

sudo iptables -A OUTPUT --protocol tcp --tcp-flags RST RST -j DROP
