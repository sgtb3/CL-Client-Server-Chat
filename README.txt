This directory contains a multi-threaded client-server chat room application.
The user needs to supply a file containing valid usernames and passwords that
hosts can log in using. A default set has been provided. Do not change the file name.
A Makefile is also provided.


The program is compiled as follows:

    make
    java Server <server port>
    java Client <server address> <server port>


An example after successfully starting the server and client
and passing username and password authentication (user):

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


Listed below are the contents of the directory:

    Makefile:   

        Command 'make' compiles the .java source files using the javac compiler. 
        Command 'make clean' will clean all auxiliary .class files.

    user_pass.txt:

        Proved by the user. This file contains only those usernames and passwords 
        credentials that a client will be able to log in using. The file needs to 
        be in plain text and can only contain alphanumeric characters, else it will
        display an error message and shutdown to allow for correction. Once the 
        server is started, it will hash these credentials using the SHA1 algorithm 
        and replace this file with another file with the same name. The original 
        file will be renamed to "user_pass.txt.OLD". The hash will also be formatted 
        in hexadecimal. Credentials need to be provided in the following format:
                
            <username> <password>
            <username> <password>
            ....

    Server.java:

        This file needs to be run before the Client.java file. The main() method
        will create a new instance of the Server class and then start the server.
        When the server starts, it will create an instance of the Inactivity
        Monitor - a thread which runs every 1/10th of a second in the background
        monitoring for dead clients and logs them out as necessary. 
        
        The server then goes into an infinite loop accepting new connections on the socket,
        and for each it creates an instance of a new thread class called Client_Thread, 
        which handles the authentication and input/output for each connected client. 
        The server also starts the shutdown hook which allows interrupt signals to be 
        caught and which attempts to close down the server gracefully, terminating any 
        open connections. 

        The server class also contains an inner class called User_Record, which holds 
        certain information which is needed by either the server or the Client_thread 
        classes. The server has lists of users and threads which can be and are accessed
        by the monitor or the client threads when needed. 

        The server uses synchronized methods any time modification to online/offline/blocked
        lists is required. This will avoid concurrent thread modification errors when/if multiple
        clients are connecting/disconnecting. 

        The server parses each line looking for the proper format for commands and will display
        and error message is the user's input does not conform.

        The server also has the ability to save and display offline messages. If a client
        receives either a group or private message while offline, the server saves it 
        and displays it to the client upon logging in. It then deletes those messages so if 
        a client logs out again they will not see old, already seen messages.

    Client.java:

        This file represents a client. The main method will create an instance of the
        Client class and then start the client. This class also contains a shutdown 
        hook in the event an interrupt signal is sent by the client. The constructor creates
        input/output streams with the server, authenticates the client, and creates an instance
        of the Server_Thread before the start client method is called. Each client has their own
        thread to communicate with the server and runs forever until either the server is shutdown,
        which in turns disconnects the client, or the client terminates - either through an 
        interrupt signal or using the 'logout' command.


Extra functionality:

    - Renames the original user_pass.txt file.
    - 'help' command.
    - Uses regex to parse text - functioning more like a terminal.
    - Offline messages
