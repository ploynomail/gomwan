package gomwan

import (
	"net"

	"github.com/google/nftables"
	"github.com/google/nftables/binaryutil"
)

func CheckWanWeight(ifs Interfaces) error {
	var totalWeight float32
	for _, inf := range ifs {
		totalWeight += inf.InitialWeight
	}
	if totalWeight > 1 {
		return ErrWansWeightLarge
	}
	return nil
}

func FilterTable(conn *nftables.Conn, tableName string) (table *nftables.Table, err error) {
	tableList, err := conn.ListTables()
	if err != nil {
		return nil, err
	}
	for _, t := range tableList {
		if t.Name == tableName {
			return t, nil
		}
	}
	return nil, nil
}

func GetAnAnonymousSet(table *nftables.Table, KeyType nftables.SetDatatype) *nftables.Set {
	return &nftables.Set{
		Table:        table,
		Anonymous:    true,
		Constant:     true,
		KeyType:      KeyType,
		KeyByteOrder: binaryutil.NativeEndian,
	}
}

func GetStartAndEndIp(cidr string) (startIP, endIP net.IP, err error) {
	_, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, nil, err
	}

	// 开始IP是IPNet结构的IP字段
	startIP = ipnet.IP

	// 结束IP是开始IP的广播地址
	endIP = make(net.IP, len(startIP))
	for i := range startIP {
		endIP[i] = startIP[i] | ^ipnet.Mask[i]
	}

	return startIP, endIP, nil
}

// incrementIP 对IP地址进行+1操作
func incrementIP(ip net.IP) net.IP {
	ipInt := ipToInt(ip)
	ipInt++
	return intToIP(ipInt)
}

// ipToInt 将IPv4地址转换为一个整数
func ipToInt(ip net.IP) uint32 {
	var ipInt uint32
	for _, octet := range ip.To4() {
		ipInt = (ipInt << 8) + uint32(octet)
	}
	return ipInt
}

// intToIP 将整数转换回IPv4地址
func intToIP(ipInt uint32) net.IP {
	ip := make(net.IP, 4)
	for i := 0; i < 4; i++ {
		ip[i] = byte((ipInt >> (24 - i*8)) & 0xFF)
	}
	return ip
}

func ipMaskTOCRDI(ipnet net.IPNet) string {
	return ipnet.String()
}
