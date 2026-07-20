package interfaces

import "net"

type Info struct {
	Index     int      `json:"index"`
	Name      string   `json:"name"`
	MAC       string   `json:"mac"`
	Addresses []string `json:"addresses"`
	Up        bool     `json:"up"`
	Loopback  bool     `json:"loopback"`
}

func Discover() ([]Info, error) {
	all, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	out := make([]Info, 0, len(all))
	for _, item := range all {
		addrs, err := item.Addrs()
		if err != nil {
			return nil, err
		}
		info := Info{Index: item.Index, Name: item.Name, MAC: item.HardwareAddr.String(), Up: item.Flags&net.FlagUp != 0, Loopback: item.Flags&net.FlagLoopback != 0}
		for _, addr := range addrs {
			info.Addresses = append(info.Addresses, addr.String())
		}
		out = append(out, info)
	}
	return out, nil
}
