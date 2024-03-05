package ipproxy

import "testing"

func BenchmarkPool(b *testing.B) {
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		buf := acquireBuffer()
		releaseBuffer(buf)
	}
}
