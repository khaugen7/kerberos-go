package kerb

import (
	"time"

	"github.com/khaugen7/kerberos-go/internal/encryption"
)

type Ticket struct {
	Username   string
	SessionKey []byte
	Validity   time.Time
}

type Autheticator struct {
	Username  string
	Timestamp time.Time
}

func GenerateTicket(username string) Ticket {
	k := encryption.GenerateRandomBytes(32)
	v := time.Now().Add(time.Hour * 1)

	return Ticket{
		Username:   username,
		SessionKey: k,
		Validity:   v,
	}
}

func ValidateClient(auth Autheticator, ticket Ticket) bool {
	return auth.Username == ticket.Username && auth.Timestamp.Before(ticket.Validity)
}