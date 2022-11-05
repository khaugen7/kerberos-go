# Kerberos-GO

This project represents a client-server application for requesting a file to be downloaded after being authenticated via the Kerberos protocol. I created this application as a learning exercise in GO and this is my first project in the language. I learned a lot and had fun during the development of this application!

*Note: This application was developed solely as a learning exercise and should not be used for authentication or management of sensitive information of any kind*

---

## Overview

This application represents a simplified version of the Kerberos authentication protocol. In my implementation, there are four components that make up the client-server infrastructure:

1. Authentication Server (AS)
2. Ticket Granting Server (TGS)
3. File Server (FS)
4. Client Application

### Kerberos Summary:

Kerberos is an authentication protocol that relies exclusively on symmetric encryption and the distribution of "service tickets" for purposes of user authentication and authorization. This means it works as a Single Sign On (SSO) protocol since the user can be authenticated once and given a validity window in which tickets may be granted without re-authenticating. My application does not yet support SSO for the client but it is something I hope to add in the future!

There are several key processes that occur during Kerberos authentication:

1. The user enters their credentials during initial authentication (note that the password was pre-shared with the AS during user setup)

2. The client sends a cleartext authentication request to the AS containing ONLY the username of the user (*not* the password)

3. If the username exists in the database, the AS will derive a secret encryption key from a salted version of the user password - this key is derived the exact same way every time

4. The AS sends two messages back to the client:

    1. A session key for client communication with the TGS - this is encrypted using the key derived from the user's pre-shared password

    2. A ticket-granting ticket (TGT) for use by the TGS - this is encrypted using a symmetric key shared between the AS and the TGS

5. The client application derives the symmetric secret key used by the AS in the exact same way - the password the user entered is hashed and the secret key is derived client-side

    - If the user entered an incorrect password then the key will not match and the data will not be decrypted - the authentication process ends here

6. The client uses this decryption key to decrypt the session key for communication with the TGS (note that the client *cannot* decrypt the TGT provided by the AS)

7. The client now generates an authenticator containing the username of the user and a timestamp for when the authenticator was created

    - This is encrypted using the session key for TGS communication

8. The client now sends a request to the TGS with two items:

    1. The authenticator object encrypted using the client-TGS session key

    2. The encrypted TGT from the AS

9. The TGS first decrypts the TGT from the AS using the shared key between the two servers

    - All Kerberos tickets contain the following items:
    
        1. The username of the authenticated user 
        
        2. The client-TGS session key that the client should be using for communication
        
        3. A validity timestamp representing the time at which the user authentication expires

10. The TGS then decrypts the client authenticator using the client-TGS session key it obtained from the TGT

    - The authenticator is then validated against the TGT - if the usernames do not match or the authenticator timestamp is beyond the validity timeout then user authentication fails and the process stops here

11. The TGS now sends two messages back to the client:

    1. A session key for client communication with the FS - this is encrypted using the client-TGS session key

    2. A service ticket (ST) for use by the FS - this is encrypted using a symmetric key shared between the TGS and the FS

12. The client uses the client-TGS session key to decrypt the session key for communication with the FS (note that the client *cannot* decrypt the ST provided by the TGS)

13. The client now generates a new authenticator with an updated timestamp

    - This is encrypted using the session key for FS communication

14. The client now sends a request to the FS with two items:

    1. The authenticator object encrypted using the client-FS session key

    2. The encrypted ST from the TGS

15. The FS first decrypts the ST from the TGS using the shared key between the two servers

16. The FS then decrypts the client authenticator using the client-FS session key it obtained from the ST

    - As before, the authenticator is validated against the ST - if the usernames do not match or the authenticator timestamp is beyond the validity timeout then user authentication fails and the process stops here

17. At this stage, the Kerberos authentication is now complete and the FS can provide the requested resource to the client application - in my implementation this is a file server providing a file for the client to download

---

## Setup

The root directory contains a Makefile for easy compilation of the application.

`make` Is the default make behaviour and generates the binaries for the AS, TGS, FS, and client applications. It places these files in a **kerberos/** subdirectory with a file structure to allow for the applications to be run right away and includes a test file to be requested by the client and served by the FS

You also have the option to compile any individual components using any of the following:

`make build-as`

`make build-tgs`

`make build-fs`

`make build-client`

Tests can be run using `make test`

The Kerberos subdirectory and all binaries within can be removed using `make clean`

---

## Components

All server components have the option to specify a path to the directory you would like the authentication database to reside in (or the path to the existing database file if it already exists)

The default behaviour is to look for the db file in the execution directory (this default behaviour works out of the box if you compiled the binaries using the `make` command and the default directory structure was created successfully)

### **kerb-as**

From the help display:

```
Usage: kerb-as [-admin] [-db PATH] [-h HOST] [-p PORT] [-help]
  -admin
        Administrator login
  -db string
        Directory for Sqlite db
  -h string
        Server host (default "127.0.0.1")
  -help
        Display help
  -p int
        Server port (default 8555)
```

The AS is responsible for the management of the authentication database and will run a first-time setup if the Sqlite database file does not exist. The AS has two distinct modes of operation: Admin and Server

#### Admin:

When using the `-admin` flag, the server operates as a CRUD application for interacting with the Sqlite user database

Login credentials: `admin admin`

From here you can Add, Find, Update, and Delete users using the menu options available to you. Note: the client user must exist in the database for the client application to authenticate successfully

### Server

In the absence of the `-admin` flag, the server operates as a regular server listening on the specified host:port combination - default is `127.0.0.1:8555`

### **kerb-tgs**

From the help display:

```
Usage: kerb-tgs [-db PATH] [-h HOST] [-p PORT] [-help]
  -db string
        Directory for Sqlite db
  -h string
        Server host (default "127.0.0.1")
  -help
        Display help
  -p int
```
The server operates as a regular server listening on the specified host:port combination - default is `127.0.0.1:8655`

### **kerb-fs**

From the help display:

```
Usage: kerb-fs [-db PATH] [-h HOST] [-p PORT] [-help]
  -db string
        Directory for Sqlite db
  -h string
        Server host (default "127.0.0.1")
  -help
        Display help
  -p int
        Server port (default 8755)
```
The server operates as a regular server listening on the specified host:port combination - default is `127.0.0.1:8755`

The FS serves files from a **files/** subdirectory - this directory structure is setup for you with the default `make` command

### **kerb-client**

From the help display:

```
Usage: kerb-client [-ash HOST] [-asp PORT] [-ash HOST] [-asp PORT] [-ash HOST] [-asp PORT]
         [-v verbose] [-help] filename
  -ash string
        Authentication server host (default "127.0.0.1")
  -asp int
        Authentication server port (default 8555)
  -fsh string
        File server host (default "127.0.0.1")
  -fsp int
        File server port (default 8755)
  -help
        Display help
  -tgsh string
        Ticket granting server host (default "127.0.0.1")
  -tgsp int
        Ticket granting server port (default 8655)
  -v    Verbose logging
filename string
        Filename to request from the server
```

The client application has options for specifying any of the host:port combinations of the various servers if you are not using the default values. 

The client also has one required argument - the filename of the file you would like to request from the FS (if using default `make` command this filename will be **test.txt**)

---

## Usage

If this is your first time running the program, you **MUST** run the `kerb-as` application first. This will initialize the authentication database. While you're in here, you should run it with the `-admin` flag and enter some users in the db - otherwise your authentication attempts will be short-lived!

Once the authentication database is initialized, the program operates as a regular client-server application. Ensure you run each of the `kerb-as` `kerb-tgs` and `kerb-fs` programs so they are actively listening for connections. Once the servers are up and running, you can run the client application. The client will prompt you for user credentials (which must exist in the authentication database) and if all goes well you should see the file you requested show up in the client directory! The kerberos authentication protocol is intended to be fairly transparent to the user but if you run the client with the `-v` flag you will see log output as the application undergoes various Kerberos checkpoints.

---

## Examples

### Running `kerb-as` for the first time:

`./kerb-as -admin`

### Running `kerb-as` with non-default database location:

`./kerb-as -db <path/to/db/file.db>`

or

`./kerb-as -db <path/to/directory/for/db>`

### Running any server with default options

`./kerb-as` `./kerb-tgs` `./kerb-fs`

### Running client with default options

`./kerb-client test.txt`

### Running client with non-default address for TGS (or any other server)

`./kerb-client -tgsh 127.0.0.2 -tgsp 9000 test.txt`