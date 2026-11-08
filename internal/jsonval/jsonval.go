// Package jsonval reads loosely typed JSON values the way the server's configuration and API
// have always read them: a number or a boolean may stand where a string is expected.
package jsonval

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
)

// Decode parses one JSON object, keeping numbers as json.Number.
func Decode(data []byte) (map[string]any, error) {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	var value any
	if err := decoder.Decode(&value); err != nil {
		return nil, err
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("trailing data after the JSON value")
	}
	object, ok := value.(map[string]any)
	if !ok {
		return nil, ErrNotObject
	}
	return object, nil
}

// ErrNotObject is returned by Decode when the JSON value is not an object.
var ErrNotObject = fmt.Errorf("expected a JSON object")

// Str is the text of a value; nil and booleans use the historical spelling.
func Str(value any) string {
	switch v := value.(type) {
	case nil:
		return "None"
	case string:
		return v
	case bool:
		if v {
			return "True"
		}
		return "False"
	default:
		return fmt.Sprint(v)
	}
}

// Truthy follows the usual rule: nil, false, zero and empty values are false.
func Truthy(value any) bool {
	switch v := value.(type) {
	case nil:
		return false
	case bool:
		return v
	case string:
		return v != ""
	case json.Number:
		number, err := v.Float64()
		return err != nil || number != 0
	case int:
		return v != 0
	case float64:
		return v != 0
	case []any:
		return len(v) > 0
	case []string:
		return len(v) > 0
	case map[string]any:
		return len(v) > 0
	default:
		return true
	}
}

// Int reads a whole number from a number, a boolean or decimal text; fractions are cut.
func Int(value any) (int64, bool) {
	switch v := value.(type) {
	case bool:
		if v {
			return 1, true
		}
		return 0, true
	case int:
		return int64(v), true
	case int64:
		return v, true
	case float64:
		return int64(v), true
	case json.Number:
		if number, err := strconv.ParseInt(v.String(), 10, 64); err == nil {
			return number, true
		}
		number, err := v.Float64()
		return int64(number), err == nil
	case string:
		number, err := strconv.ParseInt(strings.TrimSpace(v), 10, 64)
		return number, err == nil
	}
	return 0, false
}

// Float reads a number from a number, a boolean or text.
func Float(value any) (float64, bool) {
	switch v := value.(type) {
	case bool:
		if v {
			return 1, true
		}
		return 0, true
	case int:
		return float64(v), true
	case int64:
		return float64(v), true
	case float64:
		return v, true
	case json.Number:
		number, err := v.Float64()
		return number, err == nil
	case string:
		number, err := strconv.ParseFloat(strings.TrimSpace(v), 64)
		return number, err == nil
	}
	return 0, false
}
