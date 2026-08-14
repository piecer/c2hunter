package pcap

import (
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
)

type RotationReason string

const (
	RotateSize            RotationReason = "MAX_SIZE"
	RotateTime            RotationReason = "MAX_TIME"
	RotateJobEnd          RotationReason = "JOB_END"
	RotateRestart         RotationReason = "SENSOR_RESTART"
	pcapGlobalHeaderBytes int64          = 24
	pcapRecordHeaderBytes int64          = 16
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

// EstimatedWriteBytes returns the exact bytes the next packet adds, including
// a new global header when the packet opens or rotates a segment.
func (r *Rotator) EstimatedWriteBytes(info PacketInfo, dataLen int) int64 {
	recordBytes := pcapRecordHeaderBytes + int64(dataLen)
	if r.segment == nil {
		return pcapGlobalHeaderBytes + recordBytes
	}
	rotateSize := r.packets > 0 && r.limits.MaxBytes > 0 && r.bytes+recordBytes > r.limits.MaxBytes
	rotateTime := r.packets > 0 && r.limits.MaxDuration > 0 && !info.Timestamp.Before(r.started.Add(r.limits.MaxDuration))
	if rotateSize || rotateTime {
		return pcapGlobalHeaderBytes + recordBytes
	}
	return recordBytes
}

func (r *Rotator) WritePacket(info PacketInfo, data []byte) error {
	if info.CaptureLength != len(data) {
		return fmt.Errorf("capture length %d does not match data %d", info.CaptureLength, len(data))
	}
	if r.segment != nil && r.packets > 0 {
		if r.limits.MaxBytes > 0 && r.bytes+pcapRecordHeaderBytes+int64(len(data)) > r.limits.MaxBytes {
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
		r.bytes = pcapGlobalHeaderBytes
		r.index++
	}
	if err := r.segment.WritePacket(info, data); err != nil {
		return err
	}
	r.bytes += pcapRecordHeaderBytes + int64(len(data))
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
	basePath := filepath.Join(f.Directory, fmt.Sprintf("%s-%06d-%d", prefix, index, started.UnixNano()))
	finalPath, partialPath, file, err := openUniqueSegment(basePath)
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
		return nil, errors.Join(err, file.Close(), os.Remove(partialPath))
	}
	return &fileSegment{file: file, writer: writer, partialPath: partialPath, finalPath: finalPath}, nil
}

func openUniqueSegment(basePath string) (string, string, *os.File, error) {
	for sequence := 0; ; sequence++ {
		finalPath := basePath + ".pcap"
		if sequence > 0 {
			finalPath = fmt.Sprintf("%s-%d.pcap", basePath, sequence)
		}
		if _, err := os.Stat(finalPath); err == nil {
			continue
		} else if !os.IsNotExist(err) {
			return "", "", nil, err
		}
		partialPath := finalPath + ".partial"
		// #nosec G304 -- finalPath is generated under FileFactory.Directory with a fixed suffix.
		file, err := os.OpenFile(partialPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if os.IsExist(err) {
			continue
		}
		if err != nil {
			return "", "", nil, err
		}
		return finalPath, partialPath, file, nil
	}
}

func RecoverPartialSegments(directory string) error {
	entries, err := os.ReadDir(directory)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".pcap.partial") {
			continue
		}
		partial := filepath.Join(directory, entry.Name())
		recoverable, err := repairPartialSegment(partial)
		if err != nil {
			return err
		}
		if !recoverable {
			if err := quarantinePartialSegment(partial); err != nil && !os.IsNotExist(err) {
				return err
			}
			continue
		}
		finalPath := strings.TrimSuffix(partial, ".partial")
		if _, err := os.Stat(finalPath); err == nil {
			finalPath = strings.TrimSuffix(finalPath, ".pcap") + fmt.Sprintf(".recovered-%d.pcap", time.Now().UnixNano())
		} else if !os.IsNotExist(err) {
			return err
		}
		if err := os.Rename(partial, finalPath); err != nil && !os.IsNotExist(err) {
			return err
		}
	}
	return nil
}

func repairPartialSegment(path string) (bool, error) {
	// #nosec G304 -- path is a ReadDir basename joined to the scanned directory.
	file, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		return false, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return false, err
	}
	if info.Size() < pcapGlobalHeaderBytes {
		return false, nil
	}
	globalHeader := make([]byte, pcapGlobalHeaderBytes)
	if _, err := file.ReadAt(globalHeader, 0); err != nil {
		return false, err
	}
	var order binary.ByteOrder
	switch string(globalHeader[:4]) {
	case "\xd4\xc3\xb2\xa1", "\x4d\x3c\xb2\xa1":
		order = binary.LittleEndian
	case "\xa1\xb2\xc3\xd4", "\xa1\xb2\x3c\x4d":
		order = binary.BigEndian
	default:
		return false, nil
	}
	offset := int64(pcapGlobalHeaderBytes)
	recordHeader := make([]byte, pcapRecordHeaderBytes)
	for offset < info.Size() {
		if info.Size()-offset < pcapRecordHeaderBytes {
			if err := file.Truncate(offset); err != nil {
				return false, err
			}
			break
		}
		if _, err := file.ReadAt(recordHeader, offset); err != nil {
			return false, err
		}
		capturedLength := int64(order.Uint32(recordHeader[8:12]))
		recordBytes := int64(pcapRecordHeaderBytes) + capturedLength
		if recordBytes > info.Size()-offset {
			if err := file.Truncate(offset); err != nil {
				return false, err
			}
			break
		}
		offset += recordBytes
	}
	if err := file.Sync(); err != nil {
		return false, err
	}
	return true, nil
}

func quarantinePartialSegment(path string) error {
	base := strings.TrimSuffix(path, ".partial")
	return os.Rename(path, fmt.Sprintf("%s.corrupt-%d", base, time.Now().UnixNano()))
}

type fileSegment struct {
	file        *os.File
	writer      *pcapgo.Writer
	partialPath string
	finalPath   string
}

func (s *fileSegment) WritePacket(info PacketInfo, data []byte) error {
	return s.writer.WritePacket(gopacket.CaptureInfo{Timestamp: info.Timestamp, CaptureLength: info.CaptureLength, Length: info.WireLength}, data)
}
func (s *fileSegment) Close(RotationReason) error {
	if err := s.file.Sync(); err != nil {
		return errors.Join(err, s.file.Close())
	}
	if err := s.file.Close(); err != nil {
		return err
	}
	return os.Rename(s.partialPath, s.finalPath)
}
