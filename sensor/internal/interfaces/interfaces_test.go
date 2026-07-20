package interfaces

import "testing"

func TestDiscoverReturnsNamedInterfacesWithAddresses(t *testing.T) {
	items, err := Discover()
	if err != nil {
		t.Fatal(err)
	}
	if len(items) == 0 {
		t.Fatal("no interfaces discovered")
	}
	for _, item := range items {
		if item.Name == "" {
			t.Fatal("empty interface name")
		}
		if item.Index <= 0 {
			t.Fatalf("invalid index: %+v", item)
		}
	}
}
