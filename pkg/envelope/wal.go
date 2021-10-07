package envelope

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strconv"
	"sync"

	"github.com/goccy/go-json"
	"github.com/pkg/errors"
)

// Wal implements a write-ahead-log
type Wal struct {
	// mu is the internal mutex
	mu sync.RWMutex
	// path is the directory to the log
	path string
	// segments are the segments belonging to a Wal
	segments []*segment
	// closed indicates the Wal was closed
	closed bool
	// fh is the file handle for the file currently being processed
	fh *os.File
	// firstIndex is index of the first log element contained within any segment belonging to the Wal
	firstIndex uint64
	// firstIndex is index of the last log element contained within any segment belonging to the Wal
	lastIndex uint64
}

// segment represents a Wal segment
type segment struct {
	// path is the path to the segment
	path string
	// index is the index of the first log element in the segment
	index uint64
	// ebuf is the internal cache of the log elements in the segment
	ebuf []byte
	// epos is the internal cache of positions of the log elements in the segment
	epos []bpos
}

// bpos contains the position of a log element in the segment
type bpos struct {
	// pos is the index of the first byte belonging to the log element
	pos int
	// end is the index of the last byte belonging to the log element
	end int
}

// WalMode is the mode for the Wal
type WalMode int

const (
	// WalModeAppend sets the Wal to append only mode
	WalModeAppend WalMode = iota + 1
	// WalModeRead sets the Wal to read only mode
	WalModeRead
)

const (
	// WalMaxSegmentSize is the maximum size of a segment. When it is reached, a new segment is created.
	WalMaxSegmentSize = 1 * 1024 * 1024
)

func OpenOrCreateWal(path string, mode WalMode) (*Wal, uint64, error) {
	path, err := filepath.Abs(path)
	if err != nil {
		return nil, 0, errors.Wrapf(err, "wal: error getting absolute path for %s", path)
	}

	if err = os.MkdirAll(path, 0777); err != nil {
		return nil, 0, errors.Wrapf(err, "wal: error creating directories for path %s", path)
	}
	w := &Wal{
		path:   path,
		closed: false,
	}
	if err = w.load(); err != nil {
		return nil, 0, errors.Wrap(err, "wal: error loading")
	}
	return w, w.lastIndex, nil
}

// load loads all existing segments (excluding data) from the Wal path.
// For the last segment all data is loaded into the cache.
func (w *Wal) load() error {
	fis, err := ioutil.ReadDir(w.path)
	if err != nil {
		return errors.Wrap(err, "wal: error listing dir")
	}

	for _, fi := range fis {
		// iterate over known files
		name := fi.Name()
		if fi.IsDir() || len(name) != 20 {
			continue
		}
		index, err := strconv.ParseUint(name, 10, 64)
		if err != nil || index == 0 {
			continue
		}
		w.segments = append(w.segments, &segment{
			path:  filepath.Join(w.path, name),
			index: index,
		})
	}

	if len(w.segments) == 0 {
		// create log
		w.segments = append(w.segments, &segment{
			path:  filepath.Join(w.path, segmentName(1)),
			index: 1,
		})
		w.firstIndex = 1
		w.lastIndex = 0
		w.fh, err = os.Create(w.segments[0].path)
		return errors.Wrap(err, "wal: error creating log file")
	}

	w.firstIndex = w.segments[0].index
	lseg := w.segments[len(w.segments)-1]
	w.fh, err = os.OpenFile(lseg.path, os.O_WRONLY, 0666)
	if err != nil {
		return errors.Wrap(err, "wal: error opening log file for writing")
	}
	if _, err := w.fh.Seek(0, 2); err != nil {
		return errors.Wrap(err, "wal: error seeking to end of file")
	}
	if err := w.loadSegmentEntries(lseg); err != nil {
		return errors.Wrap(err, "wal: error loading last segment")
	}
	w.lastIndex = lseg.index + uint64(len(lseg.epos)) - 1
	return nil
}

// loadSegmentEntries loads the log entries in a segment
func (w *Wal) loadSegmentEntries(s *segment) error {
	data, err := ioutil.ReadFile(s.path)
	if err != nil {
		return errors.Wrap(err, "loadseg: could not read file")
	}
	ebuf := data
	var epos []bpos
	var pos int
	for exidx := s.index; len(data) > 0; exidx++ {
		n, err := loadNextEntry(data)
		if err != nil {
			return errors.Wrap(err, "loadseg: could not load entry")
		}
		data = data[n:]
		epos = append(epos, bpos{pos, pos + n})
		pos += n

	}
	s.ebuf = ebuf
	s.epos = epos
	return nil
}

// loadNextEntry finds the next entry in a log buffer
func loadNextEntry(data []byte) (int, error) {
	idx := bytes.IndexByte(data, '\n')
	if idx == -1 {
		return 0, errors.New("loadentry: could not find terminating character, logfile corrupt")
	}
	if data[0] != '{' || data[idx-1] != '}' {
		return 0, errors.New("loadentry: entry is not valid JSON, logfile corrupt")
	}
	return idx + 1, nil
}

// ReadAll reads all Envelopes from all segments contained in a Wal
func (w *Wal) ReadAll() ([]Envelope, error) {
	data := make([]Envelope, w.lastIndex)
	index := 0
	for _, s := range w.segments {
		err := w.loadSegmentEntries(s)
		if err != nil {
			return nil, errors.Wrap(err, "read: could not load segment file")
		}
		for i := 0; i < len(s.epos); i++ {
			err := json.Unmarshal(s.ebuf[s.epos[i].pos:s.epos[i].end], &data[index])
			if err != nil {
				return nil, errors.Wrapf(err, "read: could not umarshal at index %d; start=%d, end=%d", index, s.epos[i].pos, s.epos[i].end)
			}
			index += 1
		}
	}
	return data, nil
}

// Write writes Envelopes to the log
func (w *Wal) Write(es ...Envelope) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.closed {
		return errors.New("write: log closed")
	}

	// sanity check indices
	for i := 0; i < len(es); i++ {
		if es[i].Index != w.lastIndex+(uint64(i+1)) {
			return errors.Errorf("write: out of order: exp %d act %d", w.lastIndex+uint64(i+1), es[i].Index)
		}
	}

	s := w.segments[len(w.segments)-1]
	if len(s.ebuf) > WalMaxSegmentSize {
		if err := w.cycle(); err != nil {
			return errors.Wrap(err, "write: error cycling logfile")
		}
		s = w.segments[len(w.segments)-1]
	}

	mark := len(s.ebuf)
	for i := 0; i < len(es); i++ {
		var epos bpos
		//var b bytes.Buffer
		//err := json.NewEncoder(&b).EncodeWithOption(es[i], json.Debug())
		data, err := json.Marshal(es[i])
		//data := b.Bytes()
		if err != nil {
			return errors.Wrapf(err, "write: error encoding json from envelope %v", es[i])
		}
		s.ebuf, epos = w.appendEntry(s.ebuf, data)
		s.epos = append(s.epos, epos)
		if len(s.ebuf) > WalMaxSegmentSize {
			// end of capacity, cycle
			if _, err = w.fh.Write(s.ebuf[mark:]); err != nil {
				return errors.Wrap(err, "write: error writing to file")
			}
			w.lastIndex = es[i].Index
			if err = w.cycle(); err != nil {
				return errors.Wrap(err, "write: error cycling logfile")
			}
			s = w.segments[len(w.segments)-1]
			mark = 0
		}
	}

	if len(s.ebuf)-mark > 0 {
		// got data to write
		if _, err := w.fh.Write(s.ebuf[mark:]); err != nil {
			return errors.Wrap(err, "write: error writing to file")
		}
		w.lastIndex = es[len(es)-1].Index
	}
	return nil
}

// appendEntry prepares a log entry for addition to the log, adding a newline after the data
func (w *Wal) appendEntry(dst []byte, data []byte) (out []byte, epos bpos) {
	mark := len(dst)
	dst = append(dst, data...)
	dst = append(dst, '\n')
	return dst, bpos{mark, len(dst)}
}

// cycle switches to a new segment, syncing and closing the old segment and opening a new one
func (w *Wal) cycle() error {
	var err error
	if err = w.fh.Sync(); err != nil {
		return errors.Wrap(err, "cycle: error syncing file")
	}
	if err = w.fh.Close(); err != nil {
		return errors.Wrap(err, "cycle: error closing file")
	}
	s := &segment{
		index: w.lastIndex + 1,
		path:  filepath.Join(w.path, segmentName(w.lastIndex+1)),
	}

	w.fh, err = os.Create(s.path)
	if err != nil {
		return errors.Wrap(err, "cycle: error creating new log")
	}
	w.segments = append(w.segments, s)
	return nil
}

// Close closes the current segment file
func (w *Wal) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return errors.New("close: error already closed")
	}
	if err := w.fh.Sync(); err != nil {
		return errors.Wrap(err, "close: error syncing file")
	}
	if err := w.fh.Close(); err != nil {
		return errors.Wrap(err, "close: error closing file")
	}
	w.closed = true
	return nil
}

// Sync sync the current segment file to disk
func (w *Wal) Sync() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return errors.New("sync: error log closed")
	}
	return errors.Wrap(w.fh.Sync(), "sync: error syncing file")
}

// Combine merges all current segments into a big file, returning []byte of the merged file
func (w *Wal) Combine(dst string) ([]byte, error) {
	if _, err := os.Stat(dst); err == nil {
		return nil, errors.New("combine: refusing to overwrite existing file")
	}

	dstHandle, err := os.Create(dst)
	defer dstHandle.Close()
	if err != nil {
		return nil, errors.Wrapf(err, "combine: error creating target file")
	}

	var b bytes.Buffer

	for _, s := range w.segments {
		segData, err := ioutil.ReadFile(s.path)
		if err != nil {
			return nil, errors.Wrapf(err, "combine: error reading segment file %s", s.path)
		}
		_, err = dstHandle.Write(segData)
		if err != nil {
			return nil, errors.Wrapf(err, "combine: error writing segment data; segment file %s", s.path)
		}
		b.Write(segData)
	}
	return b.Bytes(), nil
}

// segmentName returns a 20-byte textual representation of an index
// for lexical ordering. This is used for the file names of log segments.
func segmentName(index uint64) string {
	return fmt.Sprintf("%020d", index)
}
