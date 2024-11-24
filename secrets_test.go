package secrets

import (
	"errors"
	"fmt"
	"os"
	"path"
	"slices"
	"testing"
)

func assertEqual[V comparable](t *testing.T, expected, actual V) {
	t.Helper()

	if expected != actual {
		t.Errorf("expected `%v` got `%v`", expected, actual)
	}
}

func assertError(t *testing.T, err error) {
	t.Helper()

	if err == nil {
		t.Errorf("expected error, got nil")
	}
}

func assertNoError(t *testing.T, err error) {
	t.Helper()

	if err != nil {
		t.Errorf("expected no error, got %v", err)
	}
}

func assertNil[V any](t *testing.T, v *V) {
	t.Helper()

	if v != nil {
		t.Errorf("expected nil, got %v", v)
	}
}

func assertNotNil[V any](t *testing.T, v *V) {
	t.Helper()

	if v == nil {
		t.Errorf("expected not nil, got %v", v)
	}
}

func toStrSlice(s []*Secret) []string {
	res := []string{}

	for _, secret := range s {
		res = append(res, secret.value)
	}

	return res
}

func TestSecret(t *testing.T) {
	t.Run("Basic", func(t *testing.T) {
		s := Secret{value: "foo"}

		assertEqual(t, "**REDACTED**", fmt.Sprintf("%v", s))
		assertEqual(t, "**REDACTED**", s.String())
		assertEqual(t, "foo", s.ExposeSecret())
	})

	t.Run("Mask", func(t *testing.T) {
		s1 := &Secret{value: "foo"}
		s2 := &Secret{value: "bar"}

		assertEqual(t, "this is a random **REDACTED** string that **REDACTED** contains the exposed secret",
			Mask("this is a random foo string that foo contains the exposed secret", s1))

		assertEqual(t, "this is a random foo string that foo contains the exposed secret",
			Mask("this is a random foo string that foo contains the exposed secret", s2))

		assertEqual(t, "this is a random **REDACTED** string that **REDACTED** contains the exposed secret",
			Mask("this is a random foo string that foo contains the exposed secret", s1, s2))

		assertEqual(t,
			errors.New("some error **REDACTED**").Error(),
			MaskErr(errors.New("some error foo"), s1).Error())
	})

	t.Run("Split", func(t *testing.T) {
		tests := []struct {
			input    string
			expected []string
		}{
			{
				input:    "foo",
				expected: []string{"foo"},
			},
			{
				input:    "foo bar",
				expected: []string{"foo", "bar"},
			},
		}

		for _, test := range tests {
			splitSecret := New(test.input).Split(" ")
			actual := toStrSlice(splitSecret)

			if !slices.Equal(test.expected, actual) {
				t.Errorf("expected %v, got %v", test.expected, actual)
			}
		}
	})

	t.Run("FromEnv", func(t *testing.T) {
		secret, err := FromEnv("DOES_NOT_EXIST_FOR_SURE")
		assertError(t, err)
		assertNil(t, secret)

		assertNoError(t, os.Setenv("THIS_WILL_EXIST", "foo"))
		secret, err = FromEnv("THIS_WILL_EXIST")
		assertNoError(t, err)
		assertNotNil(t, secret)
		assertEqual(t, secret.ExposeSecret(), "foo")

		// Cleanup:
		assertNoError(t, os.Unsetenv("THIS_WILL_EXIST"))
	})

	t.Run("FromFile", func(t *testing.T) {
		secrets, err := os.MkdirTemp("/tmp", "utest-secrets")
		assertNoError(t, err)

		defer os.RemoveAll(secrets)

		secret, err := FromFile("HEMLIZ")
		assertError(t, err)
		assertNil(t, secret)

		path := path.Join(secrets, "HEMLIZ")
		os.WriteFile(path, []byte("LOL!"), 0o644)
		secret, err = FromFile(path)
		assertError(t, err)
		assertNil(t, secret)

		assertNoError(t, os.Remove(path))

		os.WriteFile(path, []byte("OMG!"), 0o600)
		secret, err = FromFile(path)
		assertNoError(t, err)
		assertNotNil(t, secret)
		assertEqual(t, "OMG!", secret.ExposeSecret())
	})
}
