package kerb

import (
	"time"
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
