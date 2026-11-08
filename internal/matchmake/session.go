package matchmake

import (
	"bytes"
	"time"

	"github.com/lgicbd/SplatPc-Server/internal/nexstream"
)

// Session is a MatchmakeSession: the Gathering fields, then the matchmaking ones.
type Session struct {
	ID, Owner, Host                  uint32
	MinParticipants, MaxParticipants uint16
	Policy, PolicyArgument           uint32
	Flags, State                     uint32
	Description                      string
	GameMode                         uint32
	Attribs                          []uint32
	Open                             bool
	MatchmakeSystem                  uint32
	ApplicationData                  []byte
	NumParticipants                  uint32
	ProgressScore                    uint8
	SessionKey                       []byte
	Option                           uint32
	Param                            []byte // the MatchmakeParam map, encoded
	Started                          uint64
	UserPassword                     string
	ReferGID                         uint32
	UserPasswordEnabled              bool
	SystemPasswordEnabled            bool
}

func decodeSession(in *nexstream.Reader) *Session {
	s := &Session{Param: []byte{0, 0, 0, 0}}
	in.Struct(func(sub *nexstream.Reader, _ uint8) {
		s.ID = sub.U32()
		s.Owner = sub.PID()
		s.Host = sub.PID()
		s.MinParticipants = sub.U16()
		s.MaxParticipants = sub.U16()
		s.Policy = sub.U32()
		s.PolicyArgument = sub.U32()
		s.Flags = sub.U32()
		s.State = sub.U32()
		s.Description = sub.Text()
	})
	in.Struct(func(sub *nexstream.Reader, version uint8) {
		s.GameMode = sub.U32()
		s.Attribs = sub.U32s()
		s.Open = sub.Bool()
		s.MatchmakeSystem = sub.U32()
		s.ApplicationData = bytes.Clone(sub.Buffer())
		s.NumParticipants = sub.U32()
		s.ProgressScore = sub.U8()
		s.SessionKey = bytes.Clone(sub.Buffer())
		s.Option = sub.U32()
		if version >= 1 {
			s.Param = decodeParam(sub)
			s.Started = sub.U64()
		}
		if version >= 2 {
			s.UserPassword = sub.Text()
		}
		if version >= 3 {
			s.ReferGID = sub.U32()
			s.UserPasswordEnabled = sub.Bool()
			s.SystemPasswordEnabled = sub.Bool()
		}
	})
	return s
}

func (s *Session) encode(out *nexstream.Writer) {
	out.Struct(0, func(sub *nexstream.Writer) {
		sub.U32(s.ID)
		sub.PID(s.Owner)
		sub.PID(s.Host)
		sub.U16(s.MinParticipants)
		sub.U16(s.MaxParticipants)
		sub.U32(s.Policy)
		sub.U32(s.PolicyArgument)
		sub.U32(s.Flags)
		sub.U32(s.State)
		sub.Text(s.Description)
	})
	out.Struct(3, func(sub *nexstream.Writer) {
		sub.U32(s.GameMode)
		sub.U32s(s.Attribs)
		sub.Bool(s.Open)
		sub.U32(s.MatchmakeSystem)
		sub.Buffer(s.ApplicationData)
		sub.U32(s.NumParticipants)
		sub.U8(s.ProgressScore)
		sub.Buffer(s.SessionKey)
		sub.U32(s.Option)
		if !sub.StructHeader {
			return // version 0: the later fields need a header to exist
		}
		sub.Struct(0, func(param *nexstream.Writer) { param.Write(s.Param) })
		sub.U64(s.Started)
		sub.Text(s.UserPassword)
		sub.U32(s.ReferGID)
		sub.Bool(s.UserPasswordEnabled)
		sub.Bool(s.SystemPasswordEnabled)
	})
}

// decodeParam reads a MatchmakeParam (a string -> variant map) into its encoded form, kept to be
// sent back as it came.
func decodeParam(in *nexstream.Reader) []byte {
	out := nexstream.NewWriter(in.StructHeader)
	in.Struct(func(sub *nexstream.Reader, _ uint8) {
		count := sub.Count()
		out.U32(uint32(count))
		for i := 0; i < count; i++ {
			out.Text(sub.Text())
			copyVariant(sub, out)
		}
	})
	return out.Bytes()
}

func copyVariant(in *nexstream.Reader, out *nexstream.Writer) {
	kind := in.U8()
	switch kind {
	case 0:
		out.U8(kind)
	case 1: // a signed integer that is not negative travels as unsigned, like the reference server
		value := in.U64()
		if int64(value) >= 0 {
			kind = 6
		}
		out.U8(kind)
		out.U64(value)
	case 2, 5, 6:
		out.U8(kind)
		out.U64(in.U64())
	case 3:
		out.U8(kind)
		out.Bool(in.Bool())
	case 4:
		out.U8(kind)
		out.Text(in.Text())
	default:
		in.Fail()
	}
}

func skipSearchCriteria(in *nexstream.Reader) {
	in.Struct(func(sub *nexstream.Reader, _ uint8) {
		sub.Strings() // attribs
		sub.Text()    // game mode
		sub.Text()    // min participants
		sub.Text()    // max participants
		sub.Text()    // matchmake system
		sub.Bool()    // vacant only
		sub.Bool()    // exclude locked
		sub.Bool()    // exclude non host pid
		sub.U32()     // selection method
		sub.U16()     // vacant participants
	})
}

type joinRequest struct {
	session *Session // auto and create
	gid     uint32   // join
	message string
	count   uint16
}

// decodeAuto reads AutoMatchmakeParam as the game writes it: nothing after the target gids.
func decodeAuto(in *nexstream.Reader) *joinRequest {
	request := &joinRequest{}
	in.Struct(func(sub *nexstream.Reader, _ uint8) {
		request.session = decodeSession(sub)
		sub.U32s() // participants
		sub.U32()  // gid for participation check
		sub.U32()  // options
		request.message = sub.Text()
		request.count = sub.U16()
		count := sub.Count()
		for i := 0; i < count && sub.Err() == nil; i++ {
			skipSearchCriteria(sub)
		}
		sub.U32s() // target gids
	})
	return request
}

// decodeCreate reads CreateMatchmakeSessionParam (a Private Battle room).
func decodeCreate(in *nexstream.Reader) *joinRequest {
	request := &joinRequest{count: 1}
	in.Struct(func(sub *nexstream.Reader, _ uint8) {
		request.session = decodeSession(sub)
		sub.U32s() // additional participants
		sub.U32()  // gid for participation check
		sub.U32()  // options
		request.message = sub.Text()
		if sub.Remaining() >= 2 {
			request.count = sub.U16()
		}
	})
	return request
}

// decodeJoin reads JoinMatchmakeSessionParam (joining a friend's room).
func decodeJoin(in *nexstream.Reader) *joinRequest {
	request := &joinRequest{}
	in.Struct(func(sub *nexstream.Reader, _ uint8) {
		request.gid = sub.U32()
		sub.U32s() // participants
		sub.U32()  // gid for participation check
		sub.U32()  // options
		sub.U8()   // behavior
		sub.Text()
		sub.Text() // the passwords
		request.message = sub.Text()
	})
	return request
}

// event is a NotificationEvent.
type event struct {
	pid, kind, param1, param2, param3 uint32
	text                              string
}

func (e event) encode(out *nexstream.Writer) {
	out.Struct(0, func(sub *nexstream.Writer) {
		sub.PID(e.pid)
		sub.U32(e.kind)
		sub.PID(e.param1)
		sub.PID(e.param2)
		sub.Text(e.text)
		sub.PID(e.param3)
	})
}

func now() uint64 { return nexstream.DateTime(time.Now()) }
