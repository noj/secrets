package secrets

import (
	"errors"
	"fmt"
	"os"
	"path"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSecret(t *testing.T) {
	assert := assert.New(t)

	t.Run("Basic", func(t *testing.T) {
		s := Secret{value: "foo"}
		assert.Equal("**REDACTED**", fmt.Sprintf("%v", s))
		assert.Equal("**REDACTED**", s.String())
		assert.Equal("foo", s.ExposeSecret())
	})

	t.Run("Mask", func(t *testing.T) {
		s1 := &Secret{value: "foo"}
		s2 := &Secret{value: "bar"}

		assert.Equal("this is a random **REDACTED** string that **REDACTED** contains the exposed secret",
			Mask("this is a random foo string that foo contains the exposed secret", s1))

		assert.Equal("this is a random foo string that foo contains the exposed secret",
			Mask("this is a random foo string that foo contains the exposed secret", s2))

		assert.Equal("this is a random **REDACTED** string that **REDACTED** contains the exposed secret",
			Mask("this is a random foo string that foo contains the exposed secret", s1, s2))

		assert.Equal(
			errors.New("some error **REDACTED**"),
			MaskErr(errors.New("some error foo"), s1))
	})

	t.Run("Split", func(t *testing.T) {
		assert.Equal([]*Secret{New("foo")}, New("foo").Split(" "))
		assert.Equal([]*Secret{New("foo"), New("bar")}, New("foo bar").Split(" "))
	})

	t.Run("FromEnv", func(t *testing.T) {
		secret, err := FromEnv("DOES_NOT_EXIST_FOR_SURE")
		assert.Error(err)
		assert.Nil(secret)

		assert.NoError(os.Setenv("THIS_WILL_EXIST", "foo"))
		secret, err = FromEnv("THIS_WILL_EXIST")
		assert.NoError(err)
		assert.NotNil(secret)
		assert.Equal(secret.ExposeSecret(), "foo")

		// Cleanup:
		assert.NoError(os.Unsetenv("THIS_WILL_EXIST"))
	})

	t.Run("FromFile", func(t *testing.T) {
		secrets, err := os.MkdirTemp("/tmp", "utest-secrets")
		assert.NoError(err)

		defer os.RemoveAll(secrets)

		secret, err := FromFile("HEMLIZ")
		assert.Error(err)
		assert.Nil(secret)

		path := path.Join(secrets, "HEMLIZ")
		os.WriteFile(path, []byte("LOL!"), 0o644)
		secret, err = FromFile(path)
		assert.Error(err)
		assert.Nil(secret)

		assert.NoError(os.Remove(path))

		os.WriteFile(path, []byte("OMG!"), 0o600)
		secret, err = FromFile(path)
		assert.NoError(err)
		assert.NotNil(secret)
		assert.Equal("OMG!", secret.ExposeSecret())
	})
}
