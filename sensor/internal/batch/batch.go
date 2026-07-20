package batch

import "fmt"

type Queue[T any] struct {
	maxItems, maxBytes, bytes int
	size                      func(T) int
	items                     []T
}

func NewQueue[T any](maxItems, maxBytes int, size func(T) int) *Queue[T] {
	if maxItems <= 0 || maxBytes <= 0 || size == nil {
		panic("batch limits and size function are required")
	}
	return &Queue[T]{maxItems: maxItems, maxBytes: maxBytes, size: size, items: make([]T, 0, maxItems)}
}
func (q *Queue[T]) Add(v T) ([]T, error) {
	n := q.size(v)
	if n < 0 || n > q.maxBytes {
		return nil, fmt.Errorf("item size %d exceeds batch limit %d", n, q.maxBytes)
	}
	q.items = append(q.items, v)
	q.bytes += n
	if len(q.items) >= q.maxItems || q.bytes >= q.maxBytes {
		return q.Flush(), nil
	}
	return nil, nil
}
func (q *Queue[T]) Flush() []T {
	if len(q.items) == 0 {
		return nil
	}
	out := append([]T(nil), q.items...)
	q.items = q.items[:0]
	q.bytes = 0
	return out
}
func (q *Queue[T]) Len() int   { return len(q.items) }
func (q *Queue[T]) Bytes() int { return q.bytes }
