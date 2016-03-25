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

    // Main - args[0] = server port to listen on.
    public static void main(String[] args) {

        if (args.length != 1) {
            System.out.println("Usage: Server <Server Port Number>");
        }

        try {
            Server s = new Server(new ServerSocket(Integer.parseInt(args[0])));
            s.start_server();
        } catch (IOException e) {
            System.out.println("Unable to create socket on "+args[0]);
        }
    }

    // Server class environment variables.
    private final int BLOCK_TIME   = 60;                            // 60 seconds
    private final int TIME_OUT     = 30;                            // 30 minutes
    private final int MAX_ATTEMPTS = 3;
    private ServerSocket listen_socket;
    private File user_pass;
    private Inactivity_Monitor monitor;
    private Map<String, CopyOnWriteArrayList<User_Record>> BLOCKED; // based on hostname
    private CopyOnWriteArrayList<User_Record> ONLINE;               // based on username
    private CopyOnWriteArrayList<User_Record> OFFLINE;              // based on username
    private CopyOnWriteArrayList<Client_Thread> threads;            // based on thread
    private Map<String, CopyOnWriteArrayList<String>> offline_msgs; // based on hostname

    // Construct a new Server object using socket for server to listen on.
    public Server(ServerSocket sock) {

        System.setProperty("file.encoding","UTF8");
        listen_socket = sock;
        user_pass     = new File("user_pass.txt");
        BLOCKED       = new HashMap<String, CopyOnWriteArrayList<User_Record>>();
        ONLINE        = new CopyOnWriteArrayList<User_Record>();
        OFFLINE       = new CopyOnWriteArrayList<User_Record>();
        threads       = new CopyOnWriteArrayList<Client_Thread>();
        offline_msgs  = new HashMap<String, CopyOnWriteArrayList<String>>();
    }

    // Starts the server and loops forever accepting connections and creating new threads.
    private void start_server() {

        log("Server Started on port "+listen_socket.getLocalPort()+".");
        init_shutdown_hook();

        log("Inactivity Monitor thread started.");
        monitor = new Inactivity_Monitor();
        monitor.setDaemon(true);
        monitor.start();

        if (!parse_user_pass()) {
            log("Please fix " + user_pass + " file and rerun server.");
            System.exit(-1);
        }

        // loop forever accepting new connections
        log("Standing by for connections ... ");
        for ( ; ; )
        {
            Client_Thread t;
            try {
                Socket client = listen_socket.accept();
                t = new Client_Thread(this, client);
                t.setDaemon(true);
                t.start();
                add_thread(t);
            } catch (IOException e) { /* */ }
        }
    }

    // Parses the user_pass file. Returns false if non-alphanumeric chars present.
    private boolean parse_user_pass() {

        File temp_file = new File("temp");
        BufferedReader br;
        BufferedWriter bw;
        String line;

        try {

            br = new BufferedReader(new FileReader(user_pass));
            bw = new BufferedWriter(new FileWriter(temp_file));

            log("Hashing " + user_pass + "...");
            while ((line = br.readLine()) != null)
            {
                String[] tokens = line.split(" ");

                for (String t : tokens) {
                    if (!t.matches("^[a-zA-Z0-9]*$")) {// if not alphanumeric
                        return false;
                    } else {                           // else write hash to temp file
                        bw.write(get_hash(t) + " ");
                    }
                }
                bw.write("\n");
            }

        } catch (Exception e) {
            log("Error: Unsuccessful read/write to "+user_pass+"/temp files.");
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

        // rename the user_pass.txt file to save it and rename the hashed file to user_pass.txt
        String name        = user_pass.getName().replaceFirst("[.][^.]+$", "") ;
        boolean rename_old = user_pass.renameTo(new File(user_pass+".old"));
        boolean rename_tmp = temp_file.renameTo(new File(name+".txt"));

        // if renaming file failed
        if (!rename_old && !rename_tmp) {
            log("Error: Unsuccessful in renaming "+user_pass);
            return false;
        }

        //otherwise successful
        log("File successfully hashed.");
        return true;
    }

    // Hashes the string using the SHA-1, then returns it in hex format.
    private String get_hash(String msg) {

        MessageDigest m_digest = null;

        try {
            m_digest = MessageDigest.getInstance("SHA-1");
            m_digest.reset();

            try {
                m_digest.update(msg.concat(" ").getBytes("utf8"));
            } catch (NullPointerException e){
                log("Error: No input.");
                return "";
            }

        } catch (NoSuchAlgorithmException e) {
            log("Error: SHA-1 encryption failed.");
        } catch (UnsupportedEncodingException e) {
            log("Error: UTF-8 Unsupported.");
        }

        // msg is hashed - now format it to hex format
        if (m_digest != null) {
            Formatter f = new Formatter();
            for (byte b : m_digest.digest()) {
                f.format("%02x", b);
            }
            String hex = f.toString();
            f.close();
            return hex;
        }

        // return an empty string if unsuccessful
        return "";
    }

    // Logs a time stamp and the message to the server.
    private void log(String msg) {

        String time_stamp = new SimpleDateFormat("yyyyMMdd_HHmmss").
                format(Calendar.getInstance().getTime());
        System.out.println(""+time_stamp+": "+msg);
    }

    // Captures interrupt signals.
    private void init_shutdown_hook() {

        Runtime.getRuntime().addShutdownHook(new Thread() {
            @Override
            public void run() {
                try {
                    for (Client_Thread t : threads) {
                        log("Closing client @ " + t.host_address);
                        t.logout();
                    }
                    log("Server shut down");
                    monitor.interrupt();
                    listen_socket.close();
                } catch (IOException e) {
                    log("Error: Server Socket was not closed.");
                    System.exit(-1);
                }
            }
        });
    }

    // Removes a client and user name from the BLOCKED database.
    private synchronized void remove_BLOCKED(Client_Thread t,
                                             String user_name) {

        // get host's block records
        CopyOnWriteArrayList<User_Record> records = BLOCKED.get(t.host_address);

        if (user_name != null) {
            for (int j = 0; j < records.size(); j++) { // iterate through all records
                User_Record r = records.get(j);
                if (r.name != null && r.name.equals(user_name)) {
                    records.remove(r);                 // remove only that record
                }
            }
        }
    }

    // Adds a host to the blocked list. 
    private synchronized void add_BLOCKED(Client_Thread t,
                                          String name_accessed, int attempts) {

        String host = t.host_address;
        User_Record r;

        // if the blocked list contains a record matching this host
        if (BLOCKED.containsKey(host)) {
            // check each record
            for (User_Record rec : BLOCKED.get(host))
            {
                // if name accessed matches a record
                if (rec.blocked_attempted_name.equals(name_accessed)) {
                    // increment the attempts for that name only & update time
                    rec.blocked_name_attempts++;
                    rec.blocked_time_attempted = System.currentTimeMillis();

                } else {
                    // otherwise create a new record for the host for this username
                    r = new User_Record(t, "Offline_Blocked");
                    r.blocked_time_attempted = System.currentTimeMillis();
                    r.blocked_attempted_name = name_accessed;
                    r.blocked_name_attempts  = attempts;
                    r.time_out = -1;
                    BLOCKED.get(host).add(r);
                }
            }

        } else {
            // Otherwise name accessed matches no record,
            // so make a new one and add to the BLOCKED list
            r = new User_Record(t, "Offline_Blocked");
            r.blocked_time_attempted = System.currentTimeMillis();
            r.blocked_attempted_name = name_accessed;
            r.blocked_name_attempts  = attempts;
            r.time_out = -1;
            CopyOnWriteArrayList<User_Record> records_list;
            records_list = new CopyOnWriteArrayList<User_Record>();
            records_list.add(r);
            BLOCKED.put(host, records_list);
        }

        t.pw.println("Reached maximum number of password attempts. "
                +host+ " blocked for "+BLOCK_TIME+" seconds.");
        log("Blocked host "+host+" for username "+name_accessed+".");

        try {
            t.client_sock.close();
            t.br.close();
            t.pw.close();
            delete_thread(t);
        } catch (IOException e) {
            log("Error: Incomplete shutdown for user "+t.user_name);
        }
    }

    // Checks to see if the client is blocked and performs necessary actions.
    private synchronized boolean check_blocked_host(Client_Thread t,
                                                    String name) {

        String host = t.host_address;

        if (!BLOCKED.containsKey(host)) {
            return false;

        } else {
            // else check each record in database
            for (User_Record record : BLOCKED.get(host))
            {
                // if the record/key is not (null = user not logged in)
                if (record != null) {

                    long time_blocked   = record.blocked_time_attempted;
                    String attempt_name = record.blocked_attempted_name;

                    // if the name in the record matches the current attempted name
                    if (name.equals(attempt_name))
                    {
                        // in seconds
                        long elapsed = (System.currentTimeMillis()-time_blocked)/1000;
                        long remain  = BLOCK_TIME - elapsed;

                        // check to see if the host has passed the time
                        if (remain > 0) {
                            log("Attempted access from blocked host "+host
                                    +" for username "+ name +
                                    ". ("+remain+") seconds remaining.");
                            return true;

                        } else {
                            // otherwise remove only that record from blocked database
                            log("Unblocked host "+host+" for username "+name+".");
                            remove_BLOCKED(t, name);
                            return false;
                        }
                    }
                }
            }
            return false;
        }
    }

    // Saves a message for an offline user.
    private synchronized void save_message(Client_Thread sender,
                                           String user_name, String msg) {

        String time_stamp = new SimpleDateFormat("yyyyMMdd_HHmmss").
                format(Calendar.getInstance().getTime());

        if (offline_msgs.containsKey(user_name)) {
            offline_msgs.get(user_name).add(time_stamp
                    +" ["+sender.user_name+"]: "+msg);

        } else if (list_contains(OFFLINE, user_name)) {
            if (user_name != null) {
                CopyOnWriteArrayList<String> temp;
                temp = new CopyOnWriteArrayList<String>();
                temp.add(time_stamp+" ["+sender.user_name+"]: "+msg);
                offline_msgs.put(user_name, temp);
            }
        }
    }

    // Displays messages received while offline, then removes them.
    private synchronized void check_messages(Client_Thread t) {

        for (CopyOnWriteArrayList<String> messages: offline_msgs.values())
        {
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

    // Adds a user to the list of offline users.
    private synchronized void add_users_OFFLINE(Client_Thread t,
                                                String status) {

        if (!list_contains(OFFLINE, t.user_name))
        {
            User_Record r = new User_Record(t, status);
            r.host = t.host_address;
            r.blocked_time_attempted = -1;
            r.blocked_name_attempts  = -1;
            r.blocked_attempted_name = "";
            r.time_out = System.currentTimeMillis();
            OFFLINE.add(r);
        }
    }

    // Removes a user to the offline list.
    private synchronized void remove_users_OFFLINE(Client_Thread t) {

        if (t.user_name != null) {
            if (list_contains(OFFLINE, t.user_name)) {
                list_remove(OFFLINE, t.user_name);
            }
        }
    }

    // Adds a user to the online list.
    private synchronized void add_users_ONLINE(Client_Thread t) {

        if (!list_contains(ONLINE, t.user_name)) {
            ONLINE.add(new User_Record(t, "Online"));
        }
    }

    // Removes a user from the online list.
    private synchronized void remove_users_ONLINE(Client_Thread t) {

        if (list_contains(ONLINE, t.user_name)) {
            list_remove(ONLINE, t.user_name);
        }
    }

    // Returns the thread with the given user name - null if it does not exist.
    private synchronized Client_Thread get_thread(String user_name) {
        
        for (Client_Thread t : threads) {
            if (t.user_name.equals(user_name)) {
                return t;
            }
        }
        return null;
    }

    // Removes a given user from a given list.
    private synchronized void list_remove(CopyOnWriteArrayList<User_Record> list,
                                          String user_name) {

        for (int i = 0; i < list.size(); i++) {
            if (list.get(i).name.equals(user_name)) {
                list.remove(i);
            }
        }
    }

    // Returns true if the given list contains the given user.
    private synchronized boolean list_contains(CopyOnWriteArrayList<User_Record> list,
                                               String user_name) {

        for (User_Record r : list) {
            if (r.name != null && r.name.equals(user_name)) {
                return true;
            }
        }
        return false;
    }

    // Adds the thread to the list of current client threads. 
    private synchronized void add_thread(Client_Thread t) {
        threads.add(t);
    }

    // Removes the thread from the list of current client threads.
    private synchronized void delete_thread(Client_Thread t) {
        threads.remove(t);
    }

    /**
     * Send the message to user(s).
     * @param sender : The calling thread
     * @param msg    : The message to be sent
     * @param opt    : 1 - send to all online users, excluding sender
     *               : 2 - send to all online users, excluding sender, without user_name
     *               : 3 - send to only those names in the String users
     */
    private synchronized void send(Client_Thread sender,
                                   String msg, int opt, String users) {

        switch (opt) {
            case 1:
                for (Client_Thread receiver : threads) {
                    if (receiver.logged_in && receiver != sender) {
                        receiver.pw.println("[" + sender.user_name + "]: " + msg);
                    }
                }
                break;

            case 2:
                for (Client_Thread receiver : threads) {
                    if (receiver.logged_in && receiver != sender) {
                        receiver.pw.println(msg);
                    }
                }
                break;

            // send only to specific users
            case 3:
                for (String recipient : users.split(" ")) {
                    if (!sender.user_name.equals(recipient)) {
                        Client_Thread recip;
                        if (get_thread(recipient) != null) {
                            try {
                                recip = get_thread(recipient);
                                if (recip != null) {
                                    recip.pw.println("[PM-"+sender.user_name + "]: "+msg);
                                }
                            } catch (NullPointerException e) { /* */ }
                        }
                    }
                }
                break;
        }
    }

    /**
     * Validates the user login information.
     * @param name          :  The plaintext username
     * @return              :  0 - if password doesn't match username
     *                      :  1 - if username/password match
     *                      :  2 - if username is already online
     *                      :  3 - if username is unknown
     *                      : -1 - otherwise
     */
    private synchronized int validate_login(String name, String pass) {

        // if user is already in the list of online users
        if (list_contains(ONLINE, name)) {
            return 2;
        }

        // read user_pass.txt contents
        Scanner scan = null;
        try {
            scan = new Scanner(new FileReader(user_pass));
        } catch (FileNotFoundException e) {
            log("Error: Could not open user_pass.txt to validate login.");
        }

        if (scan != null) {
            while (scan.hasNextLine())
            {
                // tokenize the username and password in user_pass.txt
                String[] login_info = scan.nextLine().split(" ");
                String u_name = login_info[0];

                // if the hashed name matches the one one file
                if (u_name.equals(get_hash(name))) {
                    String u_pass = login_info[1];
                    return u_pass.equals(get_hash(pass)) ? 1 : 0;
                }
            }
            // scanner did not return so username was not found in file
            return 3;
        }
        // if something went wrong
        return -1;
    }

    // This class holds the user information to be used for online, offline, and blocked lists.
    private class User_Record {

        private String  name;
        private String  host;
        private String  status;
        private long    time_out;
        private String  blocked_attempted_name;
        private int     blocked_name_attempts;
        private long    blocked_time_attempted;

        @Override
        public String toString() {
            return host;
        }

        // Construct a user record given a status.
        private User_Record(Client_Thread t, String stat) {

            host   = t.host_address;
            status = stat;

            if (status.equals("Online")) {
                name = t.user_name;
                time_out = -1;
                blocked_attempted_name = null;
                blocked_name_attempts  = -1;
                blocked_time_attempted = -1;

            } else if (status.equals("Offline_Not_Blocked")) {
                name = t.user_name;
                time_out = t.time_last_active;
                blocked_attempted_name = null;
                blocked_name_attempts  = -1;
                blocked_time_attempted = -1;
            }
        }
    }

    // This thread monitors for inactive client threads. Runs ever 5 seconds.
    private class Inactivity_Monitor extends Thread {

        @Override
        public void run() {
            while (!listen_socket.isClosed()) {
                // traverse each thread
                for (Client_Thread t : threads)
                {
                    if (!t.isAlive() && t.user_name != null &&
                            list_contains(ONLINE, t.user_name)) {

                        log("Logging out dead user "+t.user_name+".");
                        t.logout();
                    }

                    long secs_inac = (System.currentTimeMillis() - t.time_last_active) / 1000;

                    // logout out user if logged in and inactive for a period >= TIME_OUT > 0
                    if (t.logged_in && (secs_inac >= TIME_OUT*60)
                            && secs_inac > 0) {
                        t.pw.println("Logged out due to inactivity.");
                        log("Closed inactive user "+t.user_name+" @ "+t.host_address);
                        t.logout();

                    }

                    try {
                        sleep(100);// sleep for 1/10 second
                    } catch (InterruptedException e) { /* */ }
                }
            }
            log("Inactivity Monitor shut down.");
        }
    }

    // Thread class handles communication with clients.
    private class Client_Thread extends Thread {

        private Socket client_sock;
        private Server chat_server;
        private String host_address;
        private String user_name;
        private PrintWriter pw;
        private BufferedReader br;
        private String login_msg;
        private String logout_msg;
        private volatile boolean alive;
        private volatile boolean logged_in;
        private volatile long time_last_active;

        // Construct a new client thread using client socket and reference to server.
        public Client_Thread(Server serv, Socket sock) {

            super();
            client_sock      = sock;
            chat_server      = serv;
            host_address     = client_sock.getInetAddress().getHostAddress();
            login_msg        = "";
            logout_msg       = "";
            alive            = true;
            logged_in        = false;
            time_last_active = 0;
        }

        // Handle client login.
        private void login(String name) {

            user_name        = name;
            logged_in        = true;
            time_last_active = System.currentTimeMillis();
            login_msg        = "User "+user_name+" has logged in.";

            pw.println("Welcome "+name
                    +"! Enter your command! (Type help for command options.)\n");

            // if messages were received while offline - display them
            if (offline_msgs.containsKey(name)) {
                check_messages(this);
                if (!offline_msgs.get(name).isEmpty()) {
                    for (String msg : offline_msgs.get(name)) {
                        pw.println(msg);
                    }
                }
            }
            add_users_ONLINE(this);
            remove_users_OFFLINE(this);

            // broadcast to all other users that user_name has logged in
            if (user_name != null) {
                log(login_msg);
                chat_server.send(this, login_msg, 2, "");
            }
        }

        // Handle client logout.
        private void logout() {

            alive            = false;
            logged_in        = false;
            time_last_active = System.currentTimeMillis();

            // user_name is null only if a client has not yet logged in
            if (user_name != null) {
                remove_users_ONLINE(this);
                add_users_OFFLINE(this, "Offline_Not_Blocked");
                logout_msg = "User "+user_name+" logged out.";
                log(logout_msg);
                chat_server.send(this, logout_msg, 2, "");
            }
            delete_thread(this);

            try {
                client_sock.close();
                pw.close();
                br.close();
            } catch (IOException e) {
                log("Error: Incomplete shutdown for user "+user_name);
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
        private void handle_command(String line, int option) {

            ArrayList<String> names = new ArrayList<String>();
            StringBuilder sb = new StringBuilder();
            String[] words;
            String msg;

            switch (option) {
                case 1:  // who
                    for (User_Record r : ONLINE) {
                        names.add(r.name);
                    }
                    pw.println(Arrays.toString(names.toArray()));
                    break;
                
                case 2:  // last
                    words = line.split(" ");
                    int time = Integer.parseInt(words[1]);

                    if (time >= 0 && time <= 60) {
                        // first add all online users
                        for (User_Record r : ONLINE) {
                            names.add(r.name);
                        }
                        // then add only those users w/in (time) mins
                        for (User_Record r : OFFLINE) {
                            if (!r.name.equals("null")) {
                                long time_diff = System.currentTimeMillis() - r.time_out;
                                if ((time_diff / 1000) <= (time * 60)
                                        && !names.contains(r.name)) {

                                    sb.append(r.name).append(" ");
                                    names.add(r.name);
                                }
                            }
                        }
                        pw.println(Arrays.toString(names.toArray()));

                    } else {
                        pw.println("Improper use of 'last'. Please specify time between 0-60 minutes.");
                    }
                    break;
                
                case 3:  // broadcast
                    msg = line.substring(10, line.length());
                    send(this, msg, 1, "");
                    break;
                
                case 4:  // send PM
                    words = line.split(" ");
                    String recipient = words[1];
                    for (int j = 2; j < words.length; j++) {
                        sb.append(words[j]).append(" ");
                    }
                    
                    msg = sb.toString();
                    if (list_contains(ONLINE, recipient)) {
                        send(this, msg, 3, recipient);
                    } else if (list_contains(OFFLINE, recipient)) {
                        save_message(this, recipient, msg);
                    }
                    break;
                
                case 5:   // send group msg
                    // get users between parentheses
                    int open_paren = line.indexOf("(");
                    int i;
                    for (i = open_paren; i < line.length(); i++) {
                        if (line.charAt(i) == ')') {
                            break;
                        }
                    }

                    String[] recipients = line.substring(open_paren + 1, i).split(" ");
                    msg = line.substring(i + 1, line.length());

                    String offline = "";
                    // append online users to string builder
                    for (String recip : recipients) {
                        if (list_contains(ONLINE, recip)) {
                            sb.append(recip).append(" ");
                        } else if (list_contains(OFFLINE, recip)) {
                            offline += recip + " ";
                        }
                    }
                    // check if any of the recipients were offline users
                    if (!offline.isEmpty()) {
                        String[] offline_users = offline.split(" ");
                        for (String user : offline_users) {
                            save_message(this, user, msg);
                        }
                    }

                    send(this, msg, 3, sb.toString());
                    pw.print("");
                    break;
            }
        }

        // Handles the communication to and from the client thread.
        private void handle_communication() {

            String help    = "^(help)(\\s)*";
            String last    = "^(last)(\\s)([0-9])+(\\s)*";
            String logout  = "^(logout)(\\s)*";
            String who     = "^(who)(\\s)*";
            String bcast   = "^(broadcast)(\\s)((.+)(\\s)*)+";
            String send_pm = "^(send)(\\s)+([a-zA-Z0-9])+(\\s)((.+)(\\s)*)+";
            String send_gr = "^(send)(\\s)+(\\()(([a-zA-Z0-9]+)+((\\s)?)){2,}(\\))(\\s)(((.+)(\\s)*)+)";
            String line;

            if (alive) {
                try {
                    while ((line = br.readLine()) != null)
                    {
                        if (Thread.interrupted()) {
                            break;
                        }

                        if (line.contains("\r") || line.contains("\n")) {
                            pw.println("Sorry! Lines can't contain new line characters.");

                        } else if (line.matches("^(send)(\\s)*") && !line.matches(send_gr) && !line.matches(send_pm)) {
                            pw.println("'send' command usage:\n" +
                                    "   send <user> <message>\n" +
                                    "   send (<user> <user> ... <user>) <message>");

                        } else if (line.matches("^(last)(\\s)*") && !line.matches(last)) {
                            pw.println("'last' command usage:\n" +
                                    "   last <number>");

                        } else if(line.matches("^(broadcast)(\\s)*") && !line.matches(bcast)) {
                            pw.println("'broadcast' command usage:\n" +
                                    "   broadcast <message>");

                        } else if (line.matches(who)) {
                            handle_command(null, 1);

                        } else if (line.matches(last)) {
                            handle_command(line, 2);

                        } else if (line.matches(bcast)) {
                            handle_command(line, 3);

                        } else if (line.matches(send_pm)) {
                            handle_command(line, 4);

                        } else if (line.matches(send_gr)) {
                            handle_command(line, 5);

                        } else if (line.matches(logout)) {
                            logout();

                        } else if (line.matches(help)) {
                            pw.println("commands:\n" +
                                    "   who\n" +
                                    "   last <number>\n" +
                                    "   broadcast <message>\n" +
                                    "   send <user> <message>\n" +
                                    "   send (<user> <user> ... <user>) <message>\n" +
                                    "   logout");

                        } else {
                            pw.println("Please specify one of the following commands:\n" +
                                    "   who last broadcast send logout");
                        }
                    }
                } catch (IOException e) { /* */ }
            }
            interrupt();
        }

        // Handles the user login and verifies credentials.
        private void handle_login() {

            int attempted = 0;
            int remaining;

            // while a client is connected
            label:
            while (alive) try {

                // read username
                pw.println("Username: ");
                String name = br.readLine();

                if (name == null) {
                    continue;
                }

                if (check_blocked_host(this, name)) {
                    pw.println("You have been blocked for too many attempts "+
                            "for this username. Please try again later.");
                    logout();
                }

                // otherwise prompt/read password
                name = name.replaceAll(" ", "");
                pw.println("Password: ");
                String pass = br.readLine();

                if (pass == null) {
                    continue;
                }

                pass = pass.replaceAll(" ", "");
                int result = validate_login(name, pass);
                switch (result)
                {
                    case 0:        // failed attempt
                        attempted++;
                        if (attempted == MAX_ATTEMPTS) {
                            add_BLOCKED(this, name, attempted);
                        } else {
                            remaining = MAX_ATTEMPTS - attempted;
                            pw.println("Incorrect password. "+remaining+" remaining.");
                        }
                        break;

                    case 1:        // provided valid credentials
                        login(name);
                        break label;

                    case 2:
                        pw.println("User "+name+" is already signed in.");
                        break;

                    case 3:
                        pw.println("Unknown username. Try again.");
                        break;

                    case 4:
                        logout();  // default - some error occurred
                        break;
                }
            } catch (IOException e) { /* */ }
        }

        // Handles reading/writing with users.
        @Override
        public void run() {

            log("New connection established.");
            try {

                pw = new PrintWriter(client_sock.getOutputStream(), true);
                br = new BufferedReader(new InputStreamReader(client_sock.getInputStream()));

            } catch (IOException e) {

                // in case inactivity_thread this removes client thread - this will avoid null pointer
                if (user_name == null) {
                    this.interrupt();
                    return;
                }

                log("Error: Failed to setup reader/writer for client "+user_name);
                if (this.alive) {
                    logout();
                }
            }
            handle_login();
            handle_communication();
        }
    }
}