package payloadfeature

import "testing"

func TestComputeMatchesCrossLanguageContract(t *testing.T) {
	got := Compute([]byte("beacon"))
	if got.Hash != "8a62e967fcd6dfa5d75308c37808b4668a7faf1cdb06e09ac0a7161827603887" {
		t.Fatalf("unexpected full hash: %s", got.Hash)
	}
	if got.PrefixHash != got.Hash || got.Length != 6 {
		t.Fatalf("unexpected prefix/length: %+v", got)
	}
	if got.Entropy != 2.585 || got.PrintableRatio != 1 || got.SimHash != "e627bf19152d67b3" || got.Version != "1" {
		t.Fatalf("unexpected derived features: %+v", got)
	}
}

func TestComputeHandlesEmptyShortAndBinaryValues(t *testing.T) {
	if got := Compute(nil); got != (Features{}) {
		t.Fatalf("empty payload produced features: %+v", got)
	}
	if got := Compute([]byte("xy")); got.SimHash != "08f14f07b58deb1a" {
		t.Fatalf("unexpected short SimHash: %+v", got)
	}
	got := Compute([]byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15})
	if got.Entropy != 4 || got.PrintableRatio != 0.1875 || got.SimHash != "fe226a187f2bc1af" {
		t.Fatalf("unexpected binary features: %+v", got)
	}
}
