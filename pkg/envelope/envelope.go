package envelope

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/binary"
	"time"

	"github.com/goccy/go-json"
	"github.com/mitchellh/hashstructure/v2"
	"github.com/pkg/errors"
)

type EnvelopeName string

const (
	LogMessageIvtName EnvelopeName = "lm"
)

// EnvelopeUnmarshalHandle is a function handle used for unmarshalling serialized Envelope data
type EnvelopeUnmarshalHandle func([]byte) (interface{}, error)

// envelopeUnmarshalHandles stores the EnvelopeUnmarshalHandle for each EnvelopeName
var envelopeUnmarshalHandles = make(map[EnvelopeName]EnvelopeUnmarshalHandle)

type Envelope struct {
	Type      EnvelopeName `json:"t"`                    // named type of the contained data
	Index     uint64       `json:"i,omitempty"`          // index inside a logfile, should be left empty if not logging
	Timestamp time.Time    `json:"ts,omitempty"`         // timestamp of the message. During logging, if empty will be filled with current time
	Signature string       `json:"s,omitempty" hash:"-"` // base64 encoded ed25519 signature of hashstructure.Hash converted to binary
	Data      interface{}  `json:"d"`                    // embedded data
}

type EnvelopeWithRawData struct {
	Type      EnvelopeName    `json:"t"`                    // named type of the contained data
	Index     uint64          `json:"i,omitempty"`          // index inside a logfile, should be left empty if not logging
	Timestamp time.Time       `json:"ts,omitempty"`         // timestamp of the message. During logging, if empty will be filled with current time
	Signature string          `json:"s,omitempty" hash:"-"` // base64 encoded ed25519 signature of hashstructure.Hash converted to binary
	Data      json.RawMessage `json:"d"`                    // embedded data, as a json.RawMessage
}

type LogMessageIvt struct {
	Timestamp   uint32 `json:"ts"`
	Voltage     int32  `json:"u"`
	Current     int32  `json:"i"`
	Temperature int32  `json:"temp"`
}

// Hash hashes the Envelope to return the checksum of its content
func (t *Envelope) Hash() []byte {
	//t.Timestamp, _ = time.Parse(time.RFC3339Nano, t.Timestamp.Format(time.RFC3339Nano))
	hashUint, _ := hashstructure.Hash(*t, hashstructure.FormatV2, nil)
	hashBytes := make([]byte, binary.MaxVarintLen64)
	_ = binary.PutUvarint(hashBytes, hashUint)
	return hashBytes
}

// Sign signs an envelopes Hash with a PrivateKey
func (t *Envelope) Sign(privateKey ed25519.PrivateKey) {
	t.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(privateKey, t.Hash()))
}

// Verify checks the signature is valid for the Envelope Hash
func (t *Envelope) Verify(publicKey ed25519.PublicKey) bool {
	if t.Signature == "" {
		return false
	}
	sig, err := base64.StdEncoding.DecodeString(t.Signature)
	if err != nil {
		return false
	}
	return ed25519.Verify(publicKey, t.Hash(), sig)
}

func (t *Envelope) UnmarshalJSON(bytes []byte) error {
	var e EnvelopeWithRawData
	var err error
	err = json.Unmarshal(bytes, &e)
	if err != nil {
		return err
	}

	t.Type = e.Type
	t.Index = e.Index
	t.Signature = e.Signature
	t.Timestamp = e.Timestamp

	if h, ok := envelopeUnmarshalHandles[e.Type]; ok {
		data, err := h(e.Data)
		if err != nil {
			return err
		}
		t.Data = data
	} else {
		return errors.Errorf("envelope: type with no unmarshal function during unmarshal: %s", e.Type)
	}
	return nil
}

func (t Envelope) MarshalJSON() ([]byte, error) {

	var b bytes.Buffer
	err := json.NewEncoder(&b).EncodeWithOption(t.Data, json.Debug())
	if err != nil {
		return nil, err
	}
	jsonData := b.Bytes()
	/*jsonData, err := json.Marshal(t.Data)
	if err != nil {
		return nil, err
	}*/
	e := EnvelopeWithRawData{
		Type:      t.Type,
		Index:     t.Index,
		Timestamp: t.Timestamp,
		Signature: t.Signature,
		Data:      jsonData,
	}
	if !e.Timestamp.IsZero() {
		e.Timestamp = time.Now()
	}
	return json.Marshal(e)
}
