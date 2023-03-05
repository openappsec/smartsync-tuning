package models

import (
	"encoding/binary"
	"math/big"
	"net"

	"openappsec.io/errors"
)

// StringToIntIPv4 converts string ipv4 to int
func StringToIntIPv4(ipv4 string) (int, error) {
	ip := net.ParseIP(ipv4)
	if ip == nil {
		return 0, errors.Errorf("wrong ipv4 address format. got: %s", ipv4).SetClass(errors.ClassBadInput)
	}
	ip = ip.To4()
	return int(binary.BigEndian.Uint32(ip)), nil
}

// IntToStringIPv4 converts int ipv4 to string
func IntToStringIPv4(ipInt int) string {
	ipByte := make([]byte, 4)
	binary.BigEndian.PutUint32(ipByte, uint32(ipInt))
	ip := net.IP(ipByte)
	return ip.String()
}

// StringToIntIPv6 convert string ipv6 to int
func StringToIntIPv6(ipv6 string) (*big.Int, error) {
	return big.NewInt(0).SetBytes(net.ParseIP(ipv6)), nil
}

// BigIntStringToStringIPv6 convert int ipv6 to string
func BigIntStringToStringIPv6(ipv6Numeric string) string {
	bi, ok := big.NewInt(0).SetString(ipv6Numeric, 10)
	if !ok {
		return ""
	}

	var ipNet net.IP = make([]byte, net.IPv6len)
	bi.FillBytes(ipNet)
	return ipNet.String()
}
