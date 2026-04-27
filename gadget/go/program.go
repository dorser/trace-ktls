// Wasm operator for the trace-ktls gadget.
//
// Converts raw eBPF event fields into human-readable output:
//   - dir_raw (0/1)     → direction ("TX" / "RX")
//   - data []byte       → plaintext (printable ASCII, dots for binary)
package main

import (
	api "github.com/inspektor-gadget/inspektor-gadget/wasmapi/go"
)

var (
	dirField       api.Field
	capturedField  api.Field
	dataField      api.Field
	directionField api.Field
	plaintextField api.Field
)

//go:wasmexport gadgetInit
func gadgetInit() int32 {
	ds, err := api.GetDataSource("ktls")
	if err != nil {
		api.Warnf("get datasource: %v", err)
		return 1
	}

	// Existing eBPF fields
	dirField, _ = ds.GetField("dir_raw")
	capturedField, _ = ds.GetField("captured")
	dataField, _ = ds.GetField("data")

	// New display fields
	directionField, err = ds.AddField("direction", api.Kind_String)
	if err != nil {
		api.Warnf("add direction field: %v", err)
		return 1
	}

	plaintextField, err = ds.AddField("plaintext", api.Kind_String)
	if err != nil {
		api.Warnf("add plaintext field: %v", err)
		return 1
	}

	ds.Subscribe(process, 0)
	return 0
}

func process(ds api.DataSource, data api.Data) {
	// Direction label
	dir, _ := dirField.Uint8(data)
	if dir == 0 {
		directionField.SetString(data, "TX")
	} else {
		directionField.SetString(data, "RX")
	}

	// Plaintext — read from raw data field
	captured, _ := capturedField.Uint32(data)
	if captured == 0 {
		return
	}

	// The data field is a [256]uint8 array; read it as a string
	raw, _ := dataField.String(data, 256)
	if len(raw) == 0 {
		return
	}

	if uint32(len(raw)) > captured {
		raw = raw[:captured]
	}

	plaintextField.SetString(data, toReadable([]byte(raw)))
}

// toReadable replaces non-printable bytes with '.' for display.
func toReadable(b []byte) string {
	out := make([]byte, len(b))
	for i, c := range b {
		switch {
		case c >= 32 && c <= 126:
			out[i] = c
		case c == '\n' || c == '\r' || c == '\t':
			out[i] = c
		default:
			out[i] = '.'
		}
	}
	return string(out)
}

func main() {}
