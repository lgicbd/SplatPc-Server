// Package nexstream reads and writes the NEX wire format: little-endian integers, length-prefixed
// strings and buffers, lists, and structures with an optional version header.
package nexstream

import (
	"encoding/binary"
	"errors"
	"time"
	"unicode/utf8"
)

// ErrShort is the error of a Reader that ran past its data or met an invalid value.
var ErrShort = errors.New("nexstream: truncated or invalid data")

// Reader decodes one buffer. The first failure sticks: later reads return zero values, so a
// decoder checks Err once at the end.
type Reader struct {
	data         []byte
	pos          int
	err          error
	StructHeader bool
}

func NewReader(data []byte, structHeader bool) *Reader {
	return &Reader{data: data, StructHeader: structHeader}
}

func (r *Reader) Err() error     { return r.err }
func (r *Reader) Remaining() int { return len(r.data) - r.pos }

// Fail marks the data as invalid.
func (r *Reader) Fail() { r.err = ErrShort }

// Read returns the next n bytes, without copying.
func (r *Reader) Read(n int) []byte {
	if r.err != nil {
		return nil
	}
	if n < 0 || n > r.Remaining() {
		r.Fail()
		return nil
	}
	chunk := r.data[r.pos : r.pos+n]
	r.pos += n
	return chunk
}

func (r *Reader) U8() uint8 {
	if chunk := r.Read(1); chunk != nil {
		return chunk[0]
	}
	return 0
}

func (r *Reader) U16() uint16 {
	if chunk := r.Read(2); chunk != nil {
		return binary.LittleEndian.Uint16(chunk)
	}
	return 0
}

func (r *Reader) U32() uint32 {
	if chunk := r.Read(4); chunk != nil {
		return binary.LittleEndian.Uint32(chunk)
	}
	return 0
}

func (r *Reader) U64() uint64 {
	if chunk := r.Read(8); chunk != nil {
		return binary.LittleEndian.Uint64(chunk)
	}
	return 0
}

func (r *Reader) Bool() bool  { return r.U8() != 0 }
func (r *Reader) PID() uint32 { return r.U32() }

// Text reads a string.
func (r *Reader) Text() string {
	length := int(r.U16())
	if length == 0 {
		return ""
	}
	chunk := r.Read(length)
	if chunk == nil {
		return ""
	}
	if !utf8.Valid(chunk) {
		r.Fail()
		return ""
	}
	return string(chunk[:length-1]) // without the terminator
}

func (r *Reader) Buffer() []byte  { return r.Read(int(r.U32())) }
func (r *Reader) QBuffer() []byte { return r.Read(int(r.U16())) }

// Count reads a list length. Every element takes at least a byte, so a hostile length fails here
// instead of driving a long loop.
func (r *Reader) Count() int {
	count := r.U32()
	if uint64(count) > uint64(r.Remaining()) {
		r.Fail()
		return 0
	}
	return int(count)
}

// Strings reads a list of strings.
func (r *Reader) Strings() []string {
	count := r.Count()
	list := make([]string, 0, count)
	for i := 0; i < count && r.err == nil; i++ {
		list = append(list, r.Text())
	}
	return list
}

// U32s reads a list of integers (or pids).
func (r *Reader) U32s() []uint32 {
	count := r.Count()
	list := make([]uint32, 0, count)
	for i := 0; i < count && r.err == nil; i++ {
		list = append(list, r.U32())
	}
	return list
}

// Struct decodes one level of a structure. With headers it is a version byte and a buffer the body
// must stay inside; without, the body is inline at version 0.
func (r *Reader) Struct(body func(sub *Reader, version uint8)) {
	if !r.StructHeader {
		body(r, 0)
		return
	}
	version := r.U8()
	data := r.Buffer()
	if r.err != nil {
		return
	}
	sub := NewReader(data, true)
	body(sub, version)
	if sub.err != nil {
		r.err = sub.err
	}
}

// AnyData skips a DataHolder and returns its type name and contents. Names are not checked: the
// server does not depend on what the game sends here.
func (r *Reader) AnyData() (string, []byte) {
	name := r.Text()
	r.U32() // the size of what follows, plus 4
	return name, r.Buffer()
}

// Writer encodes one buffer.
type Writer struct {
	data         []byte
	StructHeader bool
}

func NewWriter(structHeader bool) *Writer { return &Writer{StructHeader: structHeader} }

func (w *Writer) Bytes() []byte      { return w.data }
func (w *Writer) Write(chunk []byte) { w.data = append(w.data, chunk...) }
func (w *Writer) U8(value uint8)     { w.data = append(w.data, value) }
func (w *Writer) U16(value uint16)   { w.data = binary.LittleEndian.AppendUint16(w.data, value) }
func (w *Writer) U32(value uint32)   { w.data = binary.LittleEndian.AppendUint32(w.data, value) }
func (w *Writer) U64(value uint64)   { w.data = binary.LittleEndian.AppendUint64(w.data, value) }
func (w *Writer) PID(value uint32)   { w.U32(value) }

func (w *Writer) Bool(value bool) {
	if value {
		w.U8(1)
	} else {
		w.U8(0)
	}
}

// Text writes a string.
func (w *Writer) Text(value string) {
	w.U16(uint16(len(value) + 1))
	w.data = append(w.data, value...)
	w.U8(0)
}

func (w *Writer) Buffer(chunk []byte) {
	w.U32(uint32(len(chunk)))
	w.Write(chunk)
}

func (w *Writer) QBuffer(chunk []byte) {
	w.U16(uint16(len(chunk)))
	w.Write(chunk)
}

func (w *Writer) Strings(list []string) {
	w.U32(uint32(len(list)))
	for _, value := range list {
		w.Text(value)
	}
}

func (w *Writer) U32s(list []uint32) {
	w.U32(uint32(len(list)))
	for _, value := range list {
		w.U32(value)
	}
}

// Struct encodes one level of a structure; see Reader.Struct.
func (w *Writer) Struct(version uint8, body func(sub *Writer)) {
	if !w.StructHeader {
		body(w)
		return
	}
	sub := NewWriter(true)
	body(sub)
	w.U8(version)
	w.Buffer(sub.data)
}

// DateTime packs a time the way NEX does.
func DateTime(t time.Time) uint64 {
	t = t.UTC()
	return uint64(t.Second()) | uint64(t.Minute())<<6 | uint64(t.Hour())<<12 |
		uint64(t.Day())<<17 | uint64(t.Month())<<22 | uint64(t.Year())<<26
}

// Time unpacks a NEX DateTime.
func Time(value uint64) time.Time {
	return time.Date(int(value>>26), time.Month(value>>22&15), int(value>>17&31),
		int(value>>12&31), int(value>>6&63), int(value&63), 0, time.UTC)
}
