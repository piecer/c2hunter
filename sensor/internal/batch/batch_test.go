package batch

import "testing"

type item struct{ n int }

func TestQueueFlushesAtBoundsAndRejectsOversize(t *testing.T) {
	q := NewQueue[item](2, 10, func(v item) int { return v.n })
	if out, err := q.Add(item{4}); err != nil || out != nil {
		t.Fatalf("first add: %v %v", out, err)
	}
	out, err := q.Add(item{6})
	if err != nil || len(out) != 2 || q.Len() != 0 || q.Bytes() != 0 {
		t.Fatalf("flush failed: %v %v", out, err)
	}
	if _, err := q.Add(item{11}); err == nil {
		t.Fatal("oversized item accepted")
	}
}
func TestQueueFlushReturnsCopy(t *testing.T) {
	q := NewQueue[int](3, 30, func(int) int { return 1 })
	q.Add(1)
	got := q.Flush()
	got[0] = 9
	q.Add(2)
	again := q.Flush()
	if again[0] != 2 {
		t.Fatal("queue storage aliased")
	}
}
