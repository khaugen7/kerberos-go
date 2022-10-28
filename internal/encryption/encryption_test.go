package encryption

import (
	"encoding/hex"
	"reflect"
	"testing"
)

type deriveSecretKeyTest struct {
	password, salt string
	expected       string
}

type encryptTest struct {
	key    string
	data   any
	length int
}

type testData struct {
	Data string
	Num  float64
}

var deriveSecretKeyTests = []deriveSecretKeyTest{
	{"testpass", "salt", "670a009a135f98a87c5b8ad8ed22da447f18454779d5e215b8c6f3ad20084e01"},
	{"testpass", "anothersalt", "b9fc58e992e05a1f14f4565b4334724c2b38f9a08525c0dfe385f4d9fa8598b8"},
	{"anotherPass", "salt", "1c7d79debb7fc01b1f2aba08eeccb54237457d828bb851d67b726d5850d16a30"},
	{"", "", "faa6cf37609f28969804eb3d786e1b73e72e320d3b0512690a9cf5516fd5bd8c"},
}

var encryptTests = []encryptTest{
	{"670a009a135f98a87c5b8ad8ed22da447f18454779d5e215b8c6f3ad20084e01", "test data", 78},
	{"670a009a135f98a87c5b8ad8ed22da447f18454779d5e215b8c6f3ad20084e01", 24, 60},
	{"670a009a135f98a87c5b8ad8ed22da447f18454779d5e215b8c6f3ad20084e01", testData{"test", 3.14}, 108},
}

func TestDeriveSecretKey(t *testing.T) {
	for _, test := range deriveSecretKeyTests {
		if output := hex.EncodeToString(DeriveSecretKey(test.password, test.salt)); output != test.expected {
			t.Errorf("Output %s not equal to expected %s", output, test.expected)
		}
	}
}

func TestGenerateRandomBytes(t *testing.T) {
	output := GenerateRandomBytes(32)
	if len(output) != 32 {
		t.Error("Output length != 32")
	}
}

func TestEncrypt(t *testing.T) {
	for _, test := range encryptTests {
		key, _ := hex.DecodeString(test.key)
		ciphertext, _ := Encrypt(key, test.data)
		t.Logf("Output: %s", hex.EncodeToString(ciphertext))
		if output := hex.EncodeToString(ciphertext); len(output) != test.length {
			t.Errorf("Output length %d is not equal to expected length %d", len(output), test.length)
		}
	}
}

func TestDecrypt(t *testing.T) {
	for _, test := range encryptTests {
		key, _ := hex.DecodeString(test.key)
		ciphertext, _ := Encrypt(key, test.data)
		switch reflect.TypeOf(test.data).String() {
		case "string":
			var result string
			if _ = Decrypt(key, ciphertext, &result); result != test.data {
				t.Errorf("test output '%s' is not equal to expected string '%s'", result, test.data)
			}
		case "int":
			var result int
			if _ = Decrypt(key, ciphertext, &result); result != test.data {
				t.Errorf("test output '%d' is not equal to expected int '%d'", result, test.data)
			}
		case "encutils.testData":
			var result testData
			if _ = Decrypt(key, ciphertext, &result); result != test.data {
				t.Errorf("test output '%v' is not equal to expected struct '%v'", result, test.data)
			}
		}
	}
}
