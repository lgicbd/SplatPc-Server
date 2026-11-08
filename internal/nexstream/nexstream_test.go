package nexstream

import (
	"bytes"
	"testing"
	"time"
)

func TestRoundTrip(t *testing.T) {
	out := NewWriter(true)
	out.U8(1)
	out.U16(2)
	out.U32(3)
	out.U64(4)
	out.Bool(true)
	out.Text("héllo")
	out.Text("")
	out.Buffer([]byte{1, 2})
	out.QBuffer([]byte{3})
	out.U32s([]uint32{7, 8})
	out.Strings([]string{"a", "b"})

	in := NewReader(out.Bytes(), true)
	if in.U8() != 1 || in.U16() != 2 || in.U32() != 3 || in.U64() != 4 || !in.Bool() {
		t.Fatal("integers differ")
	}
	if in.Text() != "héllo" || in.Text() != "" {
		t.Fatal("strings differ")
	}
	if !bytes.Equal(in.Buffer(), []byte{1, 2}) || !bytes.Equal(in.QBuffer(), []byte{3}) {
		t.Fatal("buffers differ")
	}
	if list := in.U32s(); len(list) != 2 || list[1] != 8 {
		t.Fatalf("list = %v", list)
	}
	if list := in.Strings(); len(list) != 2 || list[1] != "b" {
		t.Fatalf("strings = %v", list)
	}
	if in.Err() != nil || in.Remaining() != 0 {
		t.Fatalf("err=%v remaining=%d", in.Err(), in.Remaining())
	}
}

func TestEmptyStringIsLengthOneThenTerminator(t *testing.T) {
	out := NewWriter(false)
	out.Text("")
	if !bytes.Equal(out.Bytes(), []byte{1, 0, 0}) {
		t.Fatalf("bytes = %v", out.Bytes())
	}
	if value := NewReader([]byte{0, 0}, false).Text(); value != "" {
		t.Fatalf("length 0 gave %q", value)
	}
}

func TestErrorsStick(t *testing.T) {
	in := NewReader([]byte{1}, false)
	if in.U32() != 0 || in.Err() == nil {
		t.Fatal("a short read must fail")
	}
	if in.U8() != 0 {
		t.Fatal("a failed reader must return zero values")
	}
}

func TestHostileLengthsFail(t *testing.T) {
	for _, data := range [][]byte{
		{0xff, 0xff, 0xff, 0x7f},       // buffer and list longer than the data
		{0xff, 0xff, 0xff, 0xff, 1, 2}, // would be negative on a 32-bit int
	} {
		if NewReader(data, false).Buffer(); NewReader(data, false).Buffer() != nil {
			t.Fatalf("buffer accepted %v", data)
		}
		in := NewReader(data, false)
		if in.Count() != 0 || in.Err() == nil {
			t.Fatalf("count accepted %v", data)
		}
	}
	if in := NewReader([]byte{2, 0, 0xff, 0}, false); in.Text() != "" || in.Err() == nil {
		t.Fatal("invalid UTF-8 must fail")
	}
}

func TestStructHeaders(t *testing.T) {
	out := NewWriter(true)
	out.Struct(3, func(sub *Writer) { sub.U32(5) })
	if !bytes.Equal(out.Bytes(), []byte{3, 4, 0, 0, 0, 5, 0, 0, 0}) {
		t.Fatalf("bytes = %v", out.Bytes())
	}
	// Trailing bytes inside the header's buffer are tolerated: newer clients add fields.
	in := NewReader([]byte{2, 5, 0, 0, 0, 5, 0, 0, 0, 9, 7}, true)
	in.Struct(func(sub *Reader, version uint8) {
		if version != 2 || sub.U32() != 5 {
			t.Fatal("struct body differs")
		}
	})
	if in.Err() != nil || in.U8() != 7 {
		t.Fatal("the stream must continue after the struct")
	}
	plain := NewWriter(false)
	plain.Struct(3, func(sub *Writer) { sub.U8(1) })
	if !bytes.Equal(plain.Bytes(), []byte{1}) {
		t.Fatalf("without headers: %v", plain.Bytes())
	}
}

func TestDateTime(t *testing.T) {
	moment := time.Date(2026, 11, 8, 13, 14, 15, 0, time.UTC)
	if got := Time(DateTime(moment)); !got.Equal(moment) {
		t.Fatalf("got %v", got)
	}
	want := uint64(15) | 14<<6 | 13<<12 | 8<<17 | 11<<22 | 2026<<26
	if DateTime(moment) != want {
		t.Fatalf("packed = %x", DateTime(moment))
	}
}
