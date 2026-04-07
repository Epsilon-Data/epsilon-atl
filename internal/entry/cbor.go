package entry

import (
	"fmt"

	"github.com/fxamacker/cbor/v2"
)

var encMode cbor.EncMode
var decMode cbor.DecMode

func init() {
	opts := cbor.CanonicalEncOptions()
	var err error
	encMode, err = opts.EncMode()
	if err != nil {
		panic(fmt.Sprintf("cbor enc mode: %v", err))
	}
	decMode, err = cbor.DecOptions{}.DecMode()
	if err != nil {
		panic(fmt.Sprintf("cbor dec mode: %v", err))
	}
}

// Marshal encodes a value using deterministic CBOR (canonical mode).
func Marshal(v interface{}) ([]byte, error) {
	return encMode.Marshal(v)
}

// Unmarshal decodes CBOR bytes into the given value.
func Unmarshal(data []byte, v interface{}) error {
	return decMode.Unmarshal(data, v)
}

// EntryType peeks at CBOR key 0 to determine entry type without full decode.
func EntryType(data []byte) (int, error) {
	var m map[int]cbor.RawMessage
	if err := decMode.Unmarshal(data, &m); err != nil {
		return 0, fmt.Errorf("peeking entry type: %w", err)
	}
	raw, ok := m[0]
	if !ok {
		return 0, fmt.Errorf("entry missing type field (key 0)")
	}
	var t int
	if err := decMode.Unmarshal(raw, &t); err != nil {
		return 0, fmt.Errorf("decoding entry type: %w", err)
	}
	return t, nil
}
