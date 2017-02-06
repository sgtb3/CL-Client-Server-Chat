import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.io.UnsupportedEncodingException;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Calendar;
import java.util.Formatter;
import java.util.HashMap;
import java.util.Map;
import java.util.Scanner;
import java.util.concurrent.CopyOnWriteArrayList;

public class Server {

    private final int MAXATTEMPTS = 3;  /* maximum number of login attempts */
    private final int BLOCKTIME = 60;   /* 60 seconds */
    private final int TIMEOUT = 30;     /* 30 minutes */
    private InactivityMonitor monitor;
    private ServerSocket listenSocket;
    private File userPass;

    private Map<String, CopyOnWriteArrayList<UserRecord>> blocked; /* based on hostname */
    private CopyOnWriteArrayList<UserRecord> online;               /* based on username */
    private CopyOnWriteArrayList<UserRecord> offline;              /* based on username */
    private CopyOnWriteArrayList<ClientThread> threads;            /* based on thread   */
    private Map<String, CopyOnWriteArrayList<String>> offlineMsgs; /* based on hostname */

    /**
     * Construct a new Server object using socket for server to listen on.
     * @param sock : The server listening socket.
     */
    public Server(ServerSocket sock) {

        System.setProperty("file.encoding", "UTF8");
        listenSocket = sock;
        userPass = new File("UserPass");
        blocked = new HashMap<String, CopyOnWriteArrayList<UserRecord>>();
        online  = new CopyOnWriteArrayList<UserRecord>();
        offline = new CopyOnWriteArrayList<UserRecord>();
        threads = new CopyOnWriteArrayList<ClientThread>();
        offlineMsgs = new HashMap<String, CopyOnWriteArrayList<String>>();
    }

    /**
     * Starts the server and loops forever accepting client connections
     * and creating new threads.
     */
    private void startServer() {

        log("Server Started on port " + listenSocket.getLocalPort() + ".");
        initShutdownHook();

        log("Inactivity Monitor thread started.");
        monitor = new InactivityMonitor();
        monitor.setDaemon(true);
        monitor.start();

        if (!parseUserPass()) {
            log("Please fix " + userPass + " file and rerun server.");
            System.exit(-1);
        }

        /* loop forever accepting new connections */
        log("Standing by for connections ... ");
        for (; ;) {
            ClientThread t;
            Socket client;
            try {
                client = listenSocket.accept();
                t = new ClientThread(this, client);
                t.setDaemon(true);
                t.start();
                addThread(t);
            } catch (IOException ignore) {}
        }
    }

    /*** This thread monitors for inactive client threads. Runs ever 1/10 s. */
    private class InactivityMonitor extends Thread {

        @Override
        public void run() {

            while (!listenSocket.isClosed()) {

                for (ClientThread t : threads) {

                    if (!t.isAlive() && t.userName != null &&
                        listContains(online, t.userName)) {
                        log("Logging out dead user " + t.userName + ".");
                        t.logout();
                    }

                    long currTime = System.currentTimeMillis();
                    long secsInactive = (currTime - t.timeLastActive) / 1000;
                    boolean loggedIn = t.loggedIn;
                    boolean overTime = (secsInactive >= TIMEOUT * 60);

                    /*
                     * logout user if logged in and inactive for a
                     * period >= TIMEOUT > 0
                     */
                    if (loggedIn && overTime && secsInactive > 0) {
                        t.pw.println("Logged out due to inactivity.");
                        log("Closed inactive user " + t.userName +
                            " @ " + t.hostAddress);
                        t.logout();
                    }

                    try {
                        sleep(100);
                    } catch (InterruptedException ignored) {}
                }
            }
            log("Inactivity Monitor shut down.");
        }
    }

    /*** Client thread class handles communication with clients. */
    private class ClientThread extends Thread {

        private Socket clientSock;
        private Server chatServer;
        private String hostAddress;
        private String userName;
        private PrintWriter pw;
        private BufferedReader br;
        private String loginMsg;
        private String logoutMsg;
        private volatile boolean alive;
        private volatile boolean loggedIn;
        private volatile long timeLastActive;

        /**
         * Constructs a new client thread.
         * @param serv : Reference to server.
         * @param sock : Client socket.
         */
        public ClientThread(Server serv, Socket sock) {

            super();
            clientSock = sock;
            chatServer = serv;
            hostAddress = clientSock.getInetAddress().getHostAddress();
            loginMsg = "";
            logoutMsg = "";
            alive = true;
            loggedIn = false;
            timeLastActive = 0;
        }

        /**
         * Handles client login process.
         * @param name : The username.
         */
        private void login(String name) {

            timeLastActive = System.currentTimeMillis();
            loginMsg = "User " + userName + " has logged in.";
            loggedIn = true;
            userName = name;

            pw.println("Welcome " + name +
                "! Enter your command! (Type help for command options.)\n");

            // if messages were received while offline - display them
            if (offlineMsgs.containsKey(name)) {
                checkMessages(this);
                if (!offlineMsgs.get(name).isEmpty()) {
                    for (String msg : offlineMsgs.get(name))
                        pw.println(msg);
                }
            }
            addUsersOnline(this);
            removeUsersOffline(this);

            /* broadcast to all other users that userName has logged in */
            if (userName != null) {
                log(loginMsg);
                chatServer.send(this, loginMsg, 2, "");
            }
        }

        /*** Handles client logout process. */
        private void logout() {

            timeLastActive = System.currentTimeMillis();
            loggedIn = false;
            alive = false;

            /* userName is null only if a client has not yet logged in */
            if (userName != null) {
                removeUsersOnline(this);
                addUsersOffline(this, "OfflineNotBlocked");
                logoutMsg = "User " + userName + " logged out.";
                log(logoutMsg);
                chatServer.send(this, logoutMsg, 2, "");
            }
            deleteThread(this);

            try {
                clientSock.close();
                pw.close();
                br.close();
            } catch (IOException e) {
                log("Error: Incomplete shutdown for user " + userName);
            }
        }

        /**
         * Handle the user commands.
         * @param line   : User input line
         * @param option : 1 - who
         *               : 2 - last
         *               : 3 - broadcast
         *               : 4 - send private message
         *               : 5 - send group message
         */
        private void handleCommand(String line, int option) {

            ArrayList<String> names = new ArrayList<String>();
            StringBuilder sb = new StringBuilder();
            String[] words;
            String msg;

            switch (option)
            {
                case 1:
                    for (UserRecord r : online)
                        names.add(r.name);
                    pw.println(Arrays.toString(names.toArray()));
                    break;

                case 2:
                    words = line.split(" ");
                    int time = Integer.parseInt(words[1]);

                    if (time >= 0 && time <= 60) {

                        /* first add all online users */
                        for (UserRecord r : online)
                            names.add(r.name);

                        /* then add only those users w/in (time) mins */
                        for (UserRecord r : offline) {
                            long diff;
                            if (!r.name.equals("null")) {
                                diff = System.currentTimeMillis() - r.timeout;
                                if ((diff / 1000) <= (time * 60) &&
                                    !names.contains(r.name)) {
                                    sb.append(r.name).append(" ");
                                    names.add(r.name);
                                }
                            }
                        }
                        pw.println(Arrays.toString(names.toArray()));

                    } else {
                        pw.println("Improper use of 'last.' " +
                                   "Please specify time between 0-60 minutes.");
                    }
                    break;

                case 3:
                    msg = line.substring(10, line.length());
                    send(this, msg, 1, "");
                    break;

                case 4:
                    words = line.split(" ");
                    String recipient = words[1];
                    for (int j = 2; j < words.length; j++)
                        sb.append(words[j]).append(" ");

                    msg = sb.toString();
                    if (listContains(online, recipient))
                        send(this, msg, 3, recipient);
                    else if (listContains(offline, recipient))
                        saveMessage(this, recipient, msg);
                    break;

                case 5:
                    /* get usernames between parentheses */
                    int openParen = line.indexOf("(");
                    int i;
                    for (i = openParen; i < line.length(); i++) {
                        if (line.charAt(i) == ')')
                            break;
                    }

                    String offline_list = "";
                    String[] recipients = line.substring(openParen + 1, i).
                                          split(" ");
                    msg = line.substring(i + 1, line.length());

                    /* append online users to string builder */
                    for (String recip : recipients) {
                        if (listContains(online, recip))
                            sb.append(recip).append(" ");
                        else if (listContains(offline, recip))
                            offline_list += recip + " ";
                    }

                    /* check if any of the recipients were offline users */
                    if (!offline.isEmpty()) {
                        String[] offlineUsers = offline_list.split(" ");
                        for (String user : offlineUsers)
                            saveMessage(this, user, msg);
                    }

                    send(this, msg, 3, sb.toString());
                    pw.print("");
                    break;
            }
        }

        /*** Handles the communication to and from the client thread. */
        private void handleCommunication() {

            String help   = "^(help)(\\s)*";
            String last   = "^(last)(\\s)([0-9])+(\\s)*";
            String logout = "^(logout)(\\s)*";
            String who    = "^(who)(\\s)*";
            String bcast  = "^(broadcast)(\\s)((.+)(\\s)*)+";
            String sendPm = "^(send)(\\s)+([a-zA-Z0-9])+(\\s)((.+)(\\s)*)+";
            String sendGr = "^(send)(\\s)+(\\()(([a-zA-Z0-9]+)+((\\s)?)){2,}" +
                             "(\\))(\\s)(((.+)(\\s)*)+)";
            String line;

            if (alive) {

                try {

                    while ((line = br.readLine()) != null) {

                        if (Thread.interrupted())
                            break;

                        if (line.contains("\r") || line.contains("\n")) {
                            pw.println("Sorry! Lines can't " +
                                       "contain new line characters.");

                        } else if (line.matches("^(send)(\\s)*") &&
                                  !line.matches(sendGr) &&
                                  !line.matches(sendPm)) {
                            pw.println("'send' command usage:\n" +
                                       "   send <user> <message>\n" +
                                       "   send (<user> <user> ... <user>) " +
                                       "<message>");

                        } else if (line.matches("^(last)(\\s)*") &&
                                  !line.matches(last)) {
                            pw.println("'last' command usage:\n" +
                                       "   last <number>");

                        } else if(line.matches("^(broadcast)(\\s)*") &&
                                 !line.matches(bcast)) {
                            pw.println("'broadcast' command usage:\n" +
                                       "   broadcast <message>");

                        } else if (line.matches(who)) {
                            handleCommand(null, 1);

                        } else if (line.matches(last)) {
                            handleCommand(line, 2);

                        } else if (line.matches(bcast)) {
                            handleCommand(line, 3);

                        } else if (line.matches(sendPm)) {
                            handleCommand(line, 4);

                        } else if (line.matches(sendGr)) {
                            handleCommand(line, 5);

                        } else if (line.matches(logout)) {
                            logout();

                        } else if (line.matches(help)) {
                            pw.println("commands:\n" +
                                    "   who\n" +
                                    "   last <number>\n" +
                                    "   broadcast <message>\n" +
                                    "   send <user> <message>\n" +
                                    "   send (<user> <user> ... <user>) " +
                                    "<message>\n   logout");

                        } else {
                            pw.println("Please specify one of the following " +
                                "commands:\n   who last broadcast send logout");
                        }
                    }

                } catch (IOException ignored) {}
            }
            interrupt();
        }

        /*** Handles the user login and verifies credentials. */
        private void handleLogin() {

            int attempted = 0;
            int remaining;

            /* while a client is connected */
            top:
            while (alive) try {

                /* read username */
                pw.println("Username: ");
                String name = br.readLine();

                if (name == null)
                    continue;

                if (checkBlockedHost(this, name)) {
                    pw.println("You have been blocked for too many attempts " +
                               "for this username. Please try again later.");
                    logout();
                }

                /* otherwise prompt/read password */
                name = name.replaceAll(" ", "");
                pw.println("Password: ");
                String pass = br.readLine();

                if (pass == null)
                    continue;

                pass = pass.replaceAll(" ", "");
                int result = validateLogin(name, pass);
                switch (result)
                {
                    /* failed attempt */
                    case 0:
                        attempted++;
                        if (attempted == MAXATTEMPTS) {
                            addBlocked(this, name, attempted);
                        } else {
                            remaining = MAXATTEMPTS - attempted;
                            pw.println("Incorrect password. " + remaining +
                                       " remaining.");
                        }
                        break;

                    /* provided valid credentials */
                    case 1:
                        login(name);
                        break top;

                    case 2:
                        pw.println("User " + name + " is already signed in.");
                        break;

                    case 3:
                        pw.println("Unknown username. Try again.");
                        break;

                    /* error occurred */
                    case 4:
                        logout();
                        break;
                }

            } catch (IOException ignored) {}
        }

        /*** Handles reading/writing with users. */
        @Override
        public void run() {

            log("New connection established.");
            try {
                pw = new PrintWriter(clientSock.getOutputStream(), true);
                br = new BufferedReader(new InputStreamReader(
                                        clientSock.getInputStream()));
            } catch (IOException e) {

                /*
                 * in case InactivityThread this removes client thread,
                 * this will avoid null pointer
                 */
                if (userName == null) {
                    this.interrupt();
                    return;
                }

                log("Error: Failed to setup reader/writer for client " +
                    userName);

                if (this.alive)
                    logout();
            }

            handleLogin();
            handleCommunication();
        }
    }

    /**
     * Parses the userPass file.
     * @return : True on successful file hashing, False if non-alphanumeric
     *           chararcters present or error occurred.
     */
    private boolean parseUserPass() {

        File tempFile = new File("temp");
        BufferedReader br;
        BufferedWriter bw;
        String line;

        try {

            br = new BufferedReader(new FileReader(userPass));
            bw = new BufferedWriter(new FileWriter(tempFile));

            log("Hashing " + userPass + "...");
            while ((line = br.readLine()) != null) {

                String[] tokens = line.split(" ");

                for (String t : tokens) {
                    if (!t.matches("^[a-zA-Z0-9]*$")) /* if not alphanumeric */
                        return false;
                    else
                        bw.write(getHash(t) + " ");  /* write hash to file */
                }

                bw.write("\n");
            }

        } catch (Exception e) {
            log("Error: Unable to read/write to " + userPass + "/temp file.");
            return false;
        }

        try {
            br.close();
            bw.close();
        } catch (NullPointerException e) {
            log("Error: Unable to close Buffered Reader/Writer.");
        } catch (IOException e) {
            log("Error: Unable to close Buffered Reader/Writer.");
        }

        /*
         * rename the userPass.txt file to save it and rename the hashed
         * file to userPass.txt
         */
        String name = userPass.getName().replaceFirst("[.][^.]+$", "");
        boolean renameOld = userPass.renameTo(new File(userPass + ".old"));
        boolean renameTmp = tempFile.renameTo(new File(name));

        /* if renaming file failed */
        if (!renameOld && !renameTmp) {
            log("Error: Unable to rename " + userPass);
            return false;
        }

        /* otherwise successful */
        log("File successfully hashed.");
        return true;
    }

    /**
     * Hashes the string using the SHA-1, then returns it in hex format.
     * @param msg : The string to be hashed.
     * @return    : The hashed string on success and empty string otherwise.
     */
    private String getHash(String msg) {

        MessageDigest mDigest = null;

        try {
            mDigest = MessageDigest.getInstance("SHA-1");
            mDigest.reset();
            try {
                mDigest.update(msg.concat(" ").getBytes("utf8"));
            } catch (NullPointerException e) {
                log("Error: No input.");
                return "";
            }

        } catch (NoSuchAlgorithmException e) {
            log("Error: SHA-1 encryption failed.");
        } catch (UnsupportedEncodingException e) {
            log("Error: UTF-8 Unsupported.");
        }

        /* msg is hashed - now format it to hex format */
        if (mDigest != null) {

            Formatter f = new Formatter();

            for (byte b : mDigest.digest())
                f.format("%02x", b);

            String hex = f.toString();
            f.close();
            return hex;
        }

        /* return empty string if unsuccessful */
        return "";
    }

    /*** Logs a time stamp and the message to the server. */
    private void log(String msg) {
        System.out.println("" + new SimpleDateFormat("yyyyMMdd_HHmmss").
                            format(Calendar.getInstance().getTime()) +
                            ": " + msg);
    }

    /*** A hook that captures interrupt signals. */
    private void initShutdownHook() {

        Runtime.getRuntime().addShutdownHook(new Thread() {
            @Override
            public void run() {
                try {
                    for (ClientThread t : threads) {
                        log("Closing client @ " + t.hostAddress);
                        t.logout();
                    }
                    log("Server shut down.");
                    monitor.interrupt();
                    listenSocket.close();
                } catch (IOException e) {
                    log("Error: Server Socket was not closed.");
                    System.exit(-1);
                }
            }
        });
    }

    /**
     * Removes a client and user name from the blocked database.
     * @param t        : The client thread.
     * @param userName : The user name to be unblocked.
     */
    private synchronized void removeBlocked(ClientThread t,
                                             String userName) {
        /* get host's block records */
        CopyOnWriteArrayList<UserRecord> records = blocked.get(t.hostAddress);

        if (userName != null) {
            for (int j = 0; j < records.size(); j++) {
                UserRecord r = records.get(j);
                if (r.name != null && r.name.equals(userName))
                    records.remove(r);         /* remove only matching record */
            }
        }
    }

    /**
     * Adds a host to the blocked list.
     * @param t            : The client thread.
     * @param nameAccessed : The name accessed.
     * @param attempts     : The number of access attempts.
     */
    private synchronized void addBlocked(ClientThread t, String nameAccessed,
                                         int attempts) {
        String host = t.hostAddress;
        UserRecord r;

        /* if the blocked list contains a record matching this host */
        if (blocked.containsKey(host)) {

            /* check each record */
            for (UserRecord rec : blocked.get(host)) {

                /* if name accessed matches a record */
                if (rec.blockedAttemptedName.equals(nameAccessed)) {

                    /* increment attempts for that name only & update time */
                    rec.blockedNameAttempts++;
                    rec.blockedTimeAttempted = System.currentTimeMillis();

                } else {

                    /* else create new record for the host for this username */
                    r = new UserRecord(t, "OfflineBlocked");
                    r.blockedTimeAttempted = System.currentTimeMillis();
                    r.blockedAttemptedName = nameAccessed;
                    r.blockedNameAttempts = attempts;
                    r.timeout = -1;
                    blocked.get(host).add(r);
                }
            }

        } else {

            /*
             * name accessed matches no record, so make a new one and
             * add to the blocked list
             */
            r = new UserRecord(t, "OfflineBlocked");
            r.blockedTimeAttempted = System.currentTimeMillis();
            r.blockedAttemptedName = nameAccessed;
            r.blockedNameAttempts  = attempts;
            r.timeout = -1;

            CopyOnWriteArrayList<UserRecord> recordsList;
            recordsList = new CopyOnWriteArrayList<UserRecord>();
            recordsList.add(r);
            blocked.put(host, recordsList);
        }

        t.pw.println("Reached maximum number of password attempts. "
                     + host + " blocked for " + BLOCKTIME + " seconds.");
        log("Blocked host " + host + " for username " + nameAccessed + ".");

        try {
            t.clientSock.close();
            t.br.close();
            t.pw.close();
            deleteThread(t);
        } catch (IOException e) {
            log("Error: Incomplete shutdown for user " + t.userName);
        }
    }

    /**
     * Checks to see if the client is blocked and performs necessary actions.
     * @param t    : The client thread.
     * @param name : The attempted user name.
     * @return     : True if host is blocked, False otherwise.
     */
    private synchronized boolean checkBlockedHost(ClientThread t, String name) {

        String host = t.hostAddress;

        if (!blocked.containsKey(host))
            return false;

        /* otherwise check each record in database */
        for (UserRecord record : blocked.get(host)) {

            /* if the record/key is not (null = user not logged in) */
            if (record != null) {

                long timeBlocked = record.blockedTimeAttempted;
                String attemptName = record.blockedAttemptedName;

                /* if the name in record matches the current attempted name */
                if (name.equals(attemptName)) {
                    long currTime = System.currentTimeMillis();
                    long secElapsed = (currTime - timeBlocked) / 1000;
                    long remain = BLOCKTIME - secElapsed;

                    /* check to see if the host has passed the time */
                    if (remain > 0) {
                        log("Attempted access from blocked host " + host +
                            " for username " + name + ". (" + remain +
                            ") seconds remaining.");
                        return true;

                    } else {
                        /* else remove only that record from blocked database */
                        log("Unblocked host " + host + " for username " +
                            name + ".");
                        removeBlocked(t, name);
                        return false;
                    }
                }
            }
        }
        return false;
    }

    /**
     * Saves a message for an offline user.
     * @param sender   : The sender client thread.
     * @param userName : The recipient's username.
     * @param msg      : The message to be saved.
     */
    private synchronized void saveMessage(ClientThread sender,String userName, 
                                          String msg) {

        String timeStamp = new SimpleDateFormat("yyyyMMdd_HHmmss").
                           format(Calendar.getInstance().getTime());

        /* if offline messages already contains userName */
        if (offlineMsgs.containsKey(userName)) {
            offlineMsgs.get(userName).
            add(timeStamp + " [" + sender.userName + "]: " + msg);

        } else if (listContains(offline, userName)) {
            if (userName != null) {
                CopyOnWriteArrayList<String> temp;
                temp = new CopyOnWriteArrayList<String>();
                temp.add(timeStamp + " [" + sender.userName + "]: " + msg);
                offlineMsgs.put(userName, temp);
            }
        }
    }

    /**
     * Displays messages received while offline, then removes them.
     * @param t : The client thread.
     */
    private synchronized void checkMessages(ClientThread t) {

        for (CopyOnWriteArrayList<String> messages: offlineMsgs.values()) {
            if (!messages.isEmpty()) {
                t.pw.println("Messages while you were offline: ");
                for (String msg : messages) {
                    t.pw.println(msg);
                    messages.remove(msg);
                }
                t.pw.println();
            }
        }
    }

    /**
     * Adds a user to the list of offline users.
     * @param t      : The client thread.
     * @param status : The status
     */
    private synchronized void addUsersOffline(ClientThread t, String status) {

        if (!listContains(offline, t.userName)) {
            UserRecord r = new UserRecord(t, status);
            r.host = t.hostAddress;
            r.blockedTimeAttempted = -1;
            r.blockedNameAttempts = -1;
            r.blockedAttemptedName = "";
            r.timeout = System.currentTimeMillis();
            offline.add(r);
        }
    }

    /**
     * Removes a user to the offline list.
     * @param t : The client thread.
     */
    private synchronized void removeUsersOffline(ClientThread t) {
        if (t.userName != null && listContains(offline, t.userName))
            listRemove(offline, t.userName);
    }

    /**
     * Adds a user to the online list.
     * @param t : The client thread.
     */
    private synchronized void addUsersOnline(ClientThread t) {
        if (!listContains(online, t.userName))
            online.add(new UserRecord(t, "Online"));
    }

    /**
     * Removes a user from the online list.
     * @param t : The client thread.
     */
    private synchronized void removeUsersOnline(ClientThread t) {
        if (listContains(online, t.userName))
            listRemove(online, t.userName);
    }

    /**
     * Returns the thread with the given user name.
     * @param userName : The user name.
     * @return         : The thread with matching userName, null otherwise.
     */
    private synchronized ClientThread getThread(String userName) {
        for (ClientThread t : threads)
            if (t.userName.equals(userName))
                return t;
        return null;
    }

    /**
     * Removes a given user from a given list.
     * @param list     : The list to be traversed.
     * @param userName : The user name.
     */
    private synchronized void listRemove(CopyOnWriteArrayList<UserRecord> list,
                                         String userName) {
        for (int i = 0; i < list.size(); i++)
            if (list.get(i).name.equals(userName))
                list.remove(i);
    }

    /**
     * Checks if the given list contains the given user.
     * @param list     : The list to be traversed.
     * @param userName : The user name to search for.
     * @return         : True if userName is in list, False otherwise.
     */
    private synchronized boolean listContains(
                    CopyOnWriteArrayList<UserRecord> list, String userName) {
        for (UserRecord r : list)
            if (r.name != null && r.name.equals(userName))
                return true;
        return false;
    }

    /**
     * Adds the thread to the list of current client threads.
     * @param t : The client thread.
     */
    private synchronized void addThread(ClientThread t) {
        threads.add(t);
    }

    /**
     * Removes the thread from the list of current client threads.
     * @param t : The client thread.
     */
    private synchronized void deleteThread(ClientThread t) {
        threads.remove(t);
    }

    /**
     * Send the message to user(s).
     * @param sender : The calling thread.
     * @param msg    : The message to be sent.
     * @param opt    : 1 - send to all online users, excluding sender.
     *               : 2 - send to all online users, excluding sender,
     *                     without userName.
     *               : 3 - send to only those names in the String users.
     */
    private synchronized void send(ClientThread sender, String msg, int opt,
                                   String users) {
        switch (opt)
        {
            case 1:
                for (ClientThread receiver : threads)
                    if (receiver.loggedIn && receiver != sender)
                        receiver.pw.println("["+ sender.userName +"]: " + msg);
                break;

            case 2:
                for (ClientThread receiver : threads)
                    if (receiver.loggedIn && receiver != sender)
                        receiver.pw.println(msg);
                break;

            case 3:
                for (String recipient : users.split(" ")) {
                    if (!sender.userName.equals(recipient)) {
                        ClientThread recip;
                        if (getThread(recipient) != null) {
                            try {
                                recip = getThread(recipient);
                                if (recip != null)
                                    recip.pw.println("[PM-" + sender.userName +
                                                     "]: " + msg);
                            } catch (NullPointerException ignored) {}
                        }
                    }
                }
                break;
        }
    }

    /**
     * Validates the user login information.
     * @param name : The username.
     * @param pass : The password.
     * @return     :  0 - if password doesn't match username
     *                1 - if username/password match
     *                2 - if username is already online
     *                3 - if username is unknown
     *               -1 - otherwise
     */
    private synchronized int validateLogin(String name, String pass) {

        /* if user is already in the list of online users */
        if (listContains(online, name))
            return 2;

        /* read userPass.txt contents */
        Scanner scan = null;
        try {
            scan = new Scanner(new FileReader(userPass));
        } catch (FileNotFoundException e) {
            log("Error: Could not open UserPass to validate login.");
        }

        if (scan == null)
            return -1;

        while (scan.hasNextLine()) {

            /* tokenize the username and password in userPass.txt */
            String[] loginInfo = scan.nextLine().split(" ");
            String uName = loginInfo[0];

            /* if the hashed name matches the one one file */
            if (uName.equals(getHash(name))) {
                String uPass = loginInfo[1];
                return uPass.equals(getHash(pass)) ? 1 : 0;
            }
        }

        /* scanner did not return so username was not found in file */
        return 3;
    }

    /*** Holds user info to be used for online, offline, and blocked lists. */
    private class UserRecord {

        private String name;
        private String host;
        private String status;
        private long timeout;
        private String blockedAttemptedName;
        private int blockedNameAttempts;
        private long blockedTimeAttempted;

        @Override
        public String toString() {
            return host;
        }

        /**
         * Constructs a user record given a status.
         * @param t    : The client thread.
         * @param stat : The status.
         */
        private UserRecord(ClientThread t, String stat) {

            host = t.hostAddress;
            status = stat;

            if (status.equals("Online")) {
                name = t.userName;
                timeout = -1;
                blockedAttemptedName = null;
                blockedNameAttempts = -1;
                blockedTimeAttempted = -1;

            } else if (status.equals("OfflineNotBlocked")) {
                name = t.userName;
                timeout = t.timeLastActive;
                blockedAttemptedName = null;
                blockedNameAttempts = -1;
                blockedTimeAttempted = -1;
            }
        }
    }

    /**
     * Server main entry point.
     * @param args : The server port number to listen on.
     */
    public static void main(String[] args) {

        if (args.length != 1) {
            System.out.println("Usage: Server <Server Port Number>");
            System.exit(-1);
        }

        try {
            Server s = new Server(new ServerSocket(Integer.parseInt(args[0])));
            s.startServer();
        } catch (IOException e) {
            System.out.println("Unable to create socket on " + args[0]);
        }
    }
}
