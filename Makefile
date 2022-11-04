KERB_AS=cmd/kerb-as
KERB_TGS=cmd/kerb-tgs
KERB_FS=cmd/kerb-fs
KERB_CLIENT=cmd/kerb-client

KERBEROS_SERVERS=kerberos/servers
TESTFILE=${KERBEROS_SERVERS}/files/test.txt
AS_BINARY=kerb-as
TGS_BINARY=kerb-tgs
FS_BINARY=kerb-fs
CLIENT_BINARY=kerb-client

build: build-as build-tgs build-fs build-client

build-as:
	go build -o ${KERBEROS_SERVERS}/${AS_BINARY} ${KERB_AS}/as.go ${KERB_AS}/as-admin.go ${KERB_AS}/as-server.go

build-tgs:
	go build -o ${KERBEROS_SERVERS}/${TGS_BINARY} ${KERB_TGS}/tgs.go

build-fs:
	go build -o ${KERBEROS_SERVERS}/${FS_BINARY} ${KERB_FS}/fs.go
	mkdir ${KERBEROS_SERVERS}/files
	echo "Test file for file server using Kerberos authentication" > ${TESTFILE}

build-client:
	go build -o kerberos/${CLIENT_BINARY} ${KERB_CLIENT}/client.go

test:
	go test ${KERB_AS}/*
	go test internal/encryption/*
	go test internal/kerb/*

clean:
	go clean
	-rm -r kerberos/
