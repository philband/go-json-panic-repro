package envelope

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"io/ioutil"
	"path/filepath"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/klauspost/pgzip"
	"github.com/pkg/errors"
	"github.com/zeebo/blake3"
)

// EnvelopeLogger implements a WAL (write-ahead-log, append only) for JSONL messages
type EnvelopeLogger struct {
	// signKey is the private key used for signing an Envelope
	signKey ed25519.PrivateKey
	// verifyKey is the public used for verifying an Envelope
	verifyKey ed25519.PublicKey
	// Buffer is the channel where messages to be written to the EnvelopeLog arrive
	Buffer chan Envelope
	// w is the internal Wal instance
	w *Wal
	// index is the current log index
	index uint64
	// mu is the mutex used for guarding operations on the index to ensure consistency
	mu sync.RWMutex
	// mode is the Wal mode
	mode WalMode
	// syncInterval is the interval with which periodic Sync calls will be made to the logfile
	syncInterval time.Duration
}

// LogMeta is the metadata written after a EnvelopeLog is combined and compressed
type LogMeta struct {
	// PublicKey is the key used to sign the log data
	PublicKey ed25519.PublicKey `json:"public_key,omitempty"`
	// LoggerId is the UUID of the logger creating the log
	LoggerId uuid.UUID `json:"logger_id,omitempty"`
	// Hash is the Blake3-256 hash of the combined logfile
	Hash string `json:"hash,omitempty"`
	// PgzHash is the Blake3-256 hash of the compressed logfile
	PgzHash string `json:"pgz_hash,omitempty"`
	// Signature is the base64 encoded signature of the combine logfile
	Signature string `json:"signature,omitempty"`
	// Timestamp is the timestamp of the log combination
	Timestamp time.Time `json:"timestamp,omitempty"`
	// StartupSequence is the boot sequence during which the log was combined
	StartupSequence int `json:"startup_sequence,omitempty"`
}

// NewEnvelopeLogger creates a new EnvelopeLogger with a path for storing the WAL and a mode indicating append or read operation.
func NewEnvelopeLogger(path string, mode WalMode) (*EnvelopeLogger, error) {
	w, idx, err := OpenOrCreateWal(path, mode)
	if err != nil {
		return nil, errors.Wrap(err, "el: error creating wal")
	}
	return &EnvelopeLogger{
		signKey:      nil,
		verifyKey:    nil,
		Buffer:       make(chan Envelope, 20),
		w:            w,
		index:        idx + 1,
		mode:         mode,
		syncInterval: 3 * time.Second,
	}, nil
}

/*
RunLogger runs the logger, persisting all incoming Envelopes to disk.
Closing the done chan will persist pending data and then close the log.
*/
func (el *EnvelopeLogger) RunLogger(ctx context.Context, done chan struct{}) error {
	defer el.w.Close()
	if el.mode != WalModeAppend {
		return errors.New("el: refusing to start log process in mode != append")
	}
	// t is the ticker for periodic Sync() calls to the wal log
	t := time.NewTicker(el.syncInterval)
	defer t.Stop()
	for {
		select {
		case <-t.C:
			// sync ticker, flush buffers to disk
			err := el.w.Sync()
			if err != nil {
				return errors.Wrap(err, "el: error in periodic file sync")
			}
		case msg, ok := <-el.Buffer:
			// receive new messages
			if !ok {
				return errors.Wrap(el.w.Close(), "el: error closing log after channel was closed")
			}

			msgBufSize := len(el.Buffer)
			msgBuf := make([]Envelope, msgBufSize+1)

			//el.mu.Lock()
			msgBuf[0] = el.prepareMessage(msg)
			for i := 1; i <= msgBufSize; i++ {
				msgBuf[i] = el.prepareMessage(<-el.Buffer)
			}

			err := el.w.Write(msgBuf...)
			//el.mu.Unlock()
			if err != nil {
				return errors.Wrap(err, "error writing to log")
			}
		case <-done:
			// we are done, write final data and closed
			for {
				select {
				case msg, ok := <-el.Buffer:
					// write pending message
					if !ok {
						return errors.Wrap(el.w.Close(), "error closing log after channel was closed")
					}
					msgBufSize := len(el.Buffer)
					msgBuf := make([]Envelope, msgBufSize+1)

					//el.mu.Lock()
					msgBuf[0] = el.prepareMessage(msg)
					for i := 1; i <= msgBufSize; i++ {
						msgBuf[i] = el.prepareMessage(<-el.Buffer)
					}

					err := el.w.Write(msgBuf...)
					//el.mu.Unlock()
					if err != nil {
						return errors.Wrap(err, "el: error writing final data to log")
					}
				case <-ctx.Done():
					// context cancelled, exit immediately
					return errors.Wrap(el.w.Close(), "el: error closing log after context was cancelled")
				case <-time.After(100 * time.Millisecond):
					// closed if no new messages have arrived in 100 ms
					return errors.Wrap(el.w.Close(), "el: error closing log after timeout")
				}
			}
		case <-ctx.Done():
			// context cancelled, exit immediately
			return errors.Wrap(el.w.Close(), "el: error closing log after context was cancelled")
		}
	}
}

// ReadAll reads all data from an EnvelopeLog, verifying all signatures
func (el *EnvelopeLogger) ReadAll() ([]Envelope, error) {
	if el.verifyKey == nil {
		return nil, errors.New("el: readall: cannot read data with no verification key set")
	}
	es, err := el.w.ReadAll()
	if err != nil {
		return nil, errors.Wrap(err, "el: readall failed")
	}
	for _, e := range es {
		if !e.Verify(el.verifyKey) {
			return nil, errors.Errorf("el: readall: failed to verify at index %d; %v", e.Index, e)
		}
	}
	return es, nil
}

// ReadAllNoVerify is the same as ReadAll, but does not attempt to verify the data
func (el *EnvelopeLogger) ReadAllNoVerify() ([]Envelope, error) {
	return el.w.ReadAll()
}

// Combine concatenates the raw EnvelopeLogs, creating a single .jsonl file. It then compresses the logfile with pgzip
// and writes a metadata file with signatures over the whole log and checksums for the compressed data.
func (el *EnvelopeLogger) Combine(dst string) error {
	if el.signKey == nil {
		return errors.Errorf("combine: cannot combine without signing key")
	}
	baseName := dst[:len(dst)-len(filepath.Ext(dst))]

	dstLog := baseName + ".jsonl"
	dstMeta := baseName + ".meta.json"
	dstLogComp := dstLog + ".pgz"

	hasher := blake3.New()

	data, err := el.w.Combine(dstLog)
	_, _ = hasher.Write(data)
	combinedHash := hasher.Sum(nil)
	if err != nil {
		return errors.Wrap(err, "combine: error combining log")
	}
	sig := ed25519.Sign(el.signKey, combinedHash)

	var b bytes.Buffer
	pgz, err := pgzip.NewWriterLevel(&b, 3)
	if err != nil {
		return errors.Wrap(err, "combine: error creating pgzip writer")
	}
	_, err = pgz.Write(data)
	if err != nil {
		return errors.Wrap(err, "combine: error compressing data")
	}
	err = pgz.Close()
	if err != nil {
		return errors.Wrap(err, "combine: error closing pgzip writer")
	}

	err = ioutil.WriteFile(dstLogComp, b.Bytes(), 0666)
	if err != nil {
		return errors.Wrap(err, "combine: error writing compressed data")
	}

	hasher.Reset()
	_, _ = hasher.Write(b.Bytes())
	pgzHash := hasher.Sum(nil)

	es := LogMeta{
		PublicKey:       el.verifyKey,
		Hash:            base64.StdEncoding.EncodeToString(combinedHash),
		PgzHash:         base64.StdEncoding.EncodeToString(pgzHash),
		Signature:       base64.StdEncoding.EncodeToString(sig),
		Timestamp:       time.Now(),
		StartupSequence: 0,
	}
	esJson, err := json.Marshal(es)
	if err != nil {
		return errors.Wrap(err, "combine: error marshalling envelope signature")
	}
	err = ioutil.WriteFile(dstMeta, esJson, 0666)
	if err != nil {
		return errors.Wrap(err, "combine: error writing envelope signature")
	}
	return nil
}

// SetSignVerifyKey sets the key to be used for signing the Envelope and the public key for verifying an Envelope.
func (el *EnvelopeLogger) SetSignVerifyKey(privateKey ed25519.PrivateKey) {
	el.signKey = privateKey
	el.verifyKey = privateKey.Public().(ed25519.PublicKey)
}

// SetVerifyKey sets the key for verify Envelope signatures
func (el *EnvelopeLogger) SetVerifyKey(publicKey ed25519.PublicKey) {
	el.verifyKey = publicKey
}

// prepareMessage sets the Envelope index, time (if not already set) and signs the Envelope
func (el *EnvelopeLogger) prepareMessage(e Envelope) Envelope {
	e.Index = el.index
	if e.Timestamp.IsZero() {
		e.Timestamp = time.Now()
	}
	el.index += 1
	if el.signKey != nil {
		e.Sign(el.signKey)
	}
	return e
}
