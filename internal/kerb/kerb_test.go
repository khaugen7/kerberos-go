package kerb

import (
	"testing"
	"time"
)

type kerbTest struct {
	auth     Autheticator
	ticket   Ticket
	expected bool
}

var auth1 = Autheticator{"username", time.Now()}
var auth2 = Autheticator{"baduser", time.Now()}
var auth3 = Autheticator{"username", time.Now().Add(time.Hour * 2)}

var ticket = Ticket{"username", []byte("somekey"), time.Now().Add(time.Hour * 1)}
var genTicket = GenerateTicket("username")

var kerbTests = []kerbTest{
	{auth1, ticket, true},
	{auth2, ticket, false},
	{auth3, ticket, false},
	{auth1, genTicket, true},
	{auth2, genTicket, false},
	{auth3, genTicket, false},
}

func TestValidation(t *testing.T) {
	for _, test := range kerbTests {
		if actual := ValidateClient(test.auth, test.ticket); actual != test.expected {
			t.Errorf("Fail: Expected %t got %t", test.expected, actual)
		}
	}
}
