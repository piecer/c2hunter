package main

import (
 "fmt"
 "net/netip"
 "time"
 "c2hunter/sensor/internal/direction"
 "c2hunter/sensor/internal/flow"
 "c2hunter/sensor/internal/flowbatch"
 "c2hunter/sensor/internal/packet"
)

func main() {
 agg := flow.NewAggregator("s1", "job", time.Second)
 at := time.Date(2026,1,1,0,0,0,0,time.UTC)
 for i, protocol := range []packet.Protocol{packet.TCP, packet.UDP} {
  agg.Add(packet.Packet{Timestamp: at, WireLength: 60, CapturedLength: 60,
   Direction: direction.Outbound, IPVersion:4,
   SourceIP:netip.MustParseAddr("10.0.0.1"), DestinationIP:netip.MustParseAddr("203.0.113.1"),
   SourcePort:50000, DestinationPort:uint16(443+i), Protocol:protocol,
   TCPFlags:packet.TCPFlags{SYN:protocol==packet.TCP},
  })
 }
 batch, err := flowbatch.New(agg.Flush()); if err != nil {panic(err)}
 data, err := flowbatch.Encode(batch); if err != nil {panic(err)}
 fmt.Println(string(data))
}
