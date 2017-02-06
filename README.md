### Contents

This directory contains a command line chat room application. The user needs to 
supply a file containing valid usernames and passwords that hosts can use to 
log in. A default set has been provided. Do not change the file name. A Makefile
is also provided.

#### Server.java
- Needs to be run before the client.
- Handles multiple, simultaneous clients.
- Contains a thread running concurrently, checking for inactive clients.
- Handles interrupt signals and terminates connections gracefully.
- Parses each line looking for the proper format for commands and 
will display an error message is the user's input does not conform.
- Has functionality to block unauthorized users for a certain amount of time 
  (60 seconds by default).
- Has functionality to save and display offline messages. If a client
receives either a group or private message while offline, the server saves it 
and displays it to the client upon logging in. It then deletes those messages.

#### Client.java
- Each client has their own thread to communicate with the server and runs 
forever until either the server is shutdown, which in turns disconnects the 
client, or the client terminates - either through an interrupt signal or 
using the `logout` command.


#### Makefile
__make__ compiles the source files
__make clean__ will clean all auxiliary files.

#### UserPass
- Contains only those usernames and passwords credentials that a client will be 
able to use to log in. 
- Needs to be in plain text and can only contain alphanumeric characters, 
else it will display an error message and shutdown to allow for correction. 
Once the server is started, it will hash these credentials using the SHA1 
algorithm and replace this file with another file with the same name. The 
original file will be renamed to "UserPass.OLD". The hash will also be formatted 
in hexadecimal. Credentials need to be provided in the following format: 

            <username> <password>
            <username> <password>
            ....

#### Build and Run
        make
        java Server <server port>
        java Client <server address> <server port>

#### Usage
An example after successfully starting the server and client, and successful 
authentication (user):

    help
    commands:
       who
       last <number>
       broadcast <message>
       send <user> <message>
       send (<user> <user> ... <user>) <message>
       logout

    who
    [user]

    broadcast hello

    last 10
    [user] 
