import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.Socket;
import java.util.NoSuchElementException;
import java.util.Scanner;

public class Client {

    private String inactiveMsg = "Logged out due to inactivity.";
    private boolean connected;
    private Socket clientSock;
    private BufferedReader br;    /* reads from the server */
    private PrintWriter pw;       /* writes to the server */
    private Scanner scan;         /* scans the user side input */

    /**
     * Construct an instance of the Client class using server IP address
     * and port number.
     * @param serverIP   : The server IP address.
     * @param serverPort : The server port.
     */
    public Client(String serverIP, int serverPort) {

        System.setProperty("file.encoding","UTF-8");
        initShutdownHook();
        connectServer(serverIP, serverPort);
        createStreams();
        authenticateUser();

        /* create and start a new thread to handle comm with server */
        ServerThread st = new ServerThread(br);
        //st.setDaemon(true);
        st.start();
    }

    /**
     * Creates a new client socket, using the given server IP and port
     * @param serverIP   : The server IP address.
     * @param serverPort : The server port number.
     */
    private void connectServer(String serverIP, int serverPort) {

        System.out.println("Establishing connection to server ... ");
        try {
            clientSock = new Socket(serverIP, serverPort);
        } catch (IOException e) {
            print("\nUnable to establish connection - server offline.", 1);
            System.exit(-1);
        }

        System.out.println("Connection to server successful.");
        connected = true;
    }

    /*** Makes input/output streams from/to the server. */
    private void createStreams() {

        try {
            scan = new Scanner(System.in);
            pw = new PrintWriter(clientSock.getOutputStream(), true);
            br = new BufferedReader(new InputStreamReader(
                                      clientSock.getInputStream()));
        } catch (IOException e) {
            print("\nUnable to create input/output stream with server.", 1);
            System.exit(-1);
        }
    }

    /*** Authenticates client. */
    private void authenticateUser() {

        /* loop twice for username and password */
        for (int i = 0; i < 2; i++) {

            /* read the prompt from the server and display to user */
            String prompt = "";

            try {
                prompt = br.readLine();
                if (prompt.equals(inactiveMsg))
                    System.exit(-1);
            } catch (IOException e) {
                print("Unable to read message from Server.", 1);
            }

            print(prompt, 2);

            /* read the user's input and send to server */
            String reply;
            if (scan.hasNextLine()) {
                reply = scan.nextLine();
                if (reply != null && !reply.isEmpty())
                    pw.println(reply);
            }
        }
    }

    /*** Continuously loops writing and reading to and from the server. */
    private void startClient() {

        while (connected) {
            try {
                while (scan.hasNextLine())
                    pw.println(scan.nextLine());
            } catch (NoSuchElementException e) {
                break;
            }
        }

        try {
            clientSock.close();
        } catch (IOException ignored) {}
    }

    /**
     * A hook that captures interrupt signals from the server.
     */
    private void initShutdownHook() {

        Runtime.getRuntime().addShutdownHook(new Thread() {
            
            @Override
            public void run() {

                connected = false;
                print("Disconnected from server.", 1);

                /* try to close out everything */
                try {
                    clientSock.close();
                    print("Closed client socket.", 1);
                    br.close();
                    pw.close();
                } catch (IOException e) {
                    print("Unable to close client sock.", 1);
                } catch (NullPointerException ignored) {}
            }
        });
    }

    /**
     * Shortens print statements to display to user.
     * @param msg : The message to be displayed.
     * @param opt : The print option.
     */
    private void print(String msg, int opt) {
        if (opt == 1)
            System.out.println(msg);
        else
            System.out.print(msg);
    }

    /*** A thread to handle communicating with server. */
    private class ServerThread extends Thread {

        private BufferedReader br;

        /**
         * Constructs a new ServerThread object.
         * @param reader : A reference to the server buffered reader.
         */
        private ServerThread(BufferedReader reader) {
            br = reader;
        }

        @Override
        public void run() {
            
            String line;
            try {
                while ((line = br.readLine()) != null) {
                    print(line, 1);
                    if (line.equals(inactiveMsg) || isInterrupted())
                        break;
                }
                System.exit(-1);
            }
            catch (IOException ignored) {}
        }
    }

    /**
     * Client main entry point.
     * @param args : The server IP address and server port number.
     */
    public static void main(String[] args) {

        if (args.length != 2) {
            System.out.println("Usage: Client <Server IP Address> " +
                               "<Server Port Number>");
            System.exit(-1);
        }

        Client c = new Client(args[0], Integer.parseInt(args[1]));
        c.startClient();
    }
}