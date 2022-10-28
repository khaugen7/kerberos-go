package main

import (
	"os"
	"testing"

	"github.com/khaugen7/kerberos-go/internal/authdb"
)

var stdinInput = "John\nDoe\njdoe42\nmypass123\n"

var expected = authdb.UserAuth{
	Id:        0,
	FirstName: "John",
	LastName:  "Doe",
	Username:  "jdoe42",
	Key:       "73301dd4c87b616cb06cfd8a3ad3686538b6eeee733768851c01698a5ffe6335",
}

func TestGatherUserInfo(t *testing.T) {
	funcDefer, err := mockStdin(t, stdinInput)
	if err != nil {
		t.Fatal(err)
	}

	defer funcDefer()

	actual := gatherUserInfo()

	if actual != expected {
		t.Errorf("Actual output %v did not match expected output %v", actual, expected)
	}
}

func mockStdin(t *testing.T, dummyInput string) (funcDefer func(), err error) {
	t.Helper()

	oldOsStdin := os.Stdin

	tmpfile, err := os.CreateTemp(t.TempDir(), t.Name())
	if err != nil {
		return nil, err
	}

	content := []byte(dummyInput)

	if _, err := tmpfile.Write(content); err != nil {
		return nil, err
	}

	if _, err := tmpfile.Seek(0, 0); err != nil {
		return nil, err
	}

	os.Stdin = tmpfile

	return func() {
		os.Stdin = oldOsStdin
		os.Remove(tmpfile.Name())
	}, nil
}
