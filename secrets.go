package secrets

import (
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"strings"
)

const redacted = "**REDACTED**"

// Boxed string that requires explicit unboxing through GetSecret for access,
// this is to avoid accidental logging of a secret value. It also makes it
// easier to audit for secrets usage in the code base.
type Secret struct {
	value string
}

// Mostly a test helper
func New(str string) *Secret {
	return &Secret{value: str}
}

// Returns the unboxed secret. The name of this function is explicitly chosen
// for ease of grep'ing.
func (s Secret) ExposeSecret() string {
	return s.value
}

// Hide value from stringification
func (Secret) String() string {
	return redacted
}

// Hide value from logging
func (Secret) LogValue() slog.Value {
	return slog.StringValue(redacted)
}

// Splits a secret according to sep and returns a slice of Secrets
func (s Secret) Split(sep string) []*Secret {
	res := make([]*Secret, 0)

	items := strings.Split(s.value, sep)
	for _, item := range items {
		res = append(res, &Secret{value: item})
	}

	return res
}

// Mask a secret possibly present in an input string
func mask(input string, secret *Secret) string {
	return strings.ReplaceAll(input, secret.value, redacted)
}

// Masks 1..n secrets in a string
func Mask(input string, secret *Secret, secrets ...*Secret) string {
	output := mask(input, secret)

	for _, secret := range secrets {
		output = mask(output, secret)
	}

	return output
}

// Masks 1..n secrets in an error message
func MaskErr(err error, secret *Secret, secrets ...*Secret) error {
	return errors.New(Mask(err.Error(), secret, secrets...))
}

// Retrieves a secret from an environment variable
func FromEnv(key string) (*Secret, error) {
	if value := os.Getenv(key); value != "" {
		return &Secret{value: value}, nil
	} else {
		return nil, fmt.Errorf("secret env var `%s` not found", key)
	}
}

// Secrets file should have non-world readable file mode
func isInsecure(mode fs.FileMode) bool {
	return mode.Perm()&0o700 != mode.Perm()
}

// Retrieves a secret from a file, the contents is whitespace trim'd.
// This is the recommended way of handling secrets.
func FromFile(filename string) (*Secret, error) {
	if finfo, err := os.Stat(filename); err == nil {
		if isInsecure(finfo.Mode()) {
			return nil, fmt.Errorf("secrets file `%s` has insecure file permissions",
				filename)
		}

		if val, err := os.ReadFile(filename); err == nil {
			return &Secret{value: strings.TrimSpace(string(val))}, nil
		}
	}

	return nil, fmt.Errorf("secrets file `%s` not found", filename)
}
