package pcap

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
)

type RotationReason string

const (
	RotateSize    RotationReason = "MAX_SIZE"
	RotateTime    RotationReason = "MAX_TIME"
	RotateJobEnd  RotationReason = "JOB_END"
	RotateRestart RotationReason = "SENSOR_RESTART"
)

type PacketInfo struct {
	Timestamp                 time.Time
	CaptureLength, WireLength int
}
type Segment interface {
	WritePacket(PacketInfo, []byte) error
	Close(RotationReason) error
}
type Factory interface {
	Open(index int, started time.Time) (Segment, error)
}
type Limits struct {
	MaxBytes    int64
	MaxDuration time.Duration
}
type Rotator struct {
	factory Factory
	limits  Limits
	segment Segment
	index   int
	started time.Time
	bytes   int64
	packets int
}

func NewRotator(factory Factory, limits Limits) (*Rotator, error) {
	if factory == nil {
		return nil, fmt.Errorf("factory is required")
	}
	if limits.MaxBytes <= 0 && limits.MaxDuration <= 0 {
		return nil, fmt.Errorf("at least one rotation limit is required")
	}
	return &Rotator{factory: factory, limits: limits}, nil
}
func (r *Rotator) WritePacket(info PacketInfo, data []byte) error {
	if info.CaptureLength != len(data) {
		return fmt.Errorf("capture length %d does not match data %d", info.CaptureLength, len(data))
	}
	if r.segment != nil && r.packets > 0 {
		if r.limits.MaxBytes > 0 && r.bytes+int64(len(data)) > r.limits.MaxBytes {
			if err := r.rotate(RotateSize); err != nil {
				return err
			}
		} else if r.limits.MaxDuration > 0 && !info.Timestamp.Before(r.started.Add(r.limits.MaxDuration)) {
			if err := r.rotate(RotateTime); err != nil {
				return err
			}
		}
	}
	if r.segment == nil {
		segment, err := r.factory.Open(r.index, info.Timestamp)
		if err != nil {
			return err
		}
		r.segment = segment
		r.started = info.Timestamp
		r.index++
	}
	if err := r.segment.WritePacket(info, data); err != nil {
		return err
	}
	r.bytes += int64(len(data))
	r.packets++
	return nil
}
func (r *Rotator) Rotate(reason RotationReason) error { return r.rotate(reason) }
func (r *Rotator) rotate(reason RotationReason) error {
	if r.segment == nil {
		return nil
	}
	err := r.segment.Close(reason)
	r.segment = nil
	r.bytes = 0
	r.packets = 0
	return err
}
func (r *Rotator) Close() error { return r.rotate(RotateJobEnd) }

type FileFactory struct {
	Directory, Prefix string
	Snaplen           uint32
	LinkType          layers.LinkType
}

func (f FileFactory) Open(index int, started time.Time) (Segment, error) {
	if err := os.MkdirAll(f.Directory, 0700); err != nil {
		return nil, err
	}
	prefix := f.Prefix
	if prefix == "" {
		prefix = "capture"
	}
	path := filepath.Join(f.Directory, fmt.Sprintf("%s-%06d-%d.pcap", prefix, index, started.UnixNano()))
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return nil, err
	}
	snaplen := f.Snaplen
	if snaplen == 0 {
		snaplen = 65535
	}
	link := f.LinkType
	if link == 0 {
		link = layers.LinkTypeEthernet
	}
	writer := pcapgo.NewWriter(file)
	if err := writer.WriteFileHeader(snaplen, link); err != nil {
		file.Close()
		return nil, err
	}
	return &fileSegment{file: file, writer: writer}, nil
}

type fileSegment struct {
	file   *os.File
	writer *pcapgo.Writer
}

func (s *fileSegment) WritePacket(info PacketInfo, data []byte) error {
	return s.writer.WritePacket(gopacket.CaptureInfo{Timestamp: info.Timestamp, CaptureLength: info.CaptureLength, Length: info.WireLength}, data)
}
func (s *fileSegment) Close(RotationReason) error { return s.file.Close() }
