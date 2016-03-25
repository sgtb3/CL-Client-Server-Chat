import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.Socket;
import java.util.NoSuchElementException;
import java.util.Scanner;

public class Client {

    // Client class environment variables
    private String inactive_msg = "Logged out due to inactivity.";
    private boolean connected;

    private Socket client_sock;
    private BufferedReader br;    // reads from the server
    private PrintWriter pw;       // writes to the server
    private Scanner scan;         // scans the user side input

    // Construct an instance of the Client class using server ip and port number
    public Client(String server_IP, int server_port) {

        System.setProperty("file.encoding","UTF-8");
        init_shutdown_hook();
        connect_server(server_IP, server_port);
        create_streams();
        authenticate_user();

        // create and start a new thread to handle comm with server
        Server_Thread st = new Server_Thread(br);
        st.setDaemon(true);
        st.start();
    }

    // Creates a new client socket, using the given server IP and port
    private void connect_server(String server_IP, int server_port) {

        System.out.println("Establishing connection to server ... ");
        try {
            client_sock = new Socket(server_IP, server_port);
        } catch (IOException e) {
            print("\nUnable to establish connection - server offline.", 1);
            System.exit(-1);
        }

        System.out.println("Connection to server successful.");
        connected = true;
    }

    // Makes input/output streams from/to the server
    private void create_streams() {

        try {
            scan = new Scanner(System.in);
            pw   = new PrintWriter(client_sock.getOutputStream(), true);
            br   = new BufferedReader(new InputStreamReader(client_sock.getInputStream()));

        } catch (IOException e) {
            print("\nUnable to create input/output stream with server.", 1);
            System.exit(-1);
        }
    }

    // Authenticates client
    private void authenticate_user() {

        // loop twice for username and password
        for (int i = 0; i < 2; i++)
        {
            // read the prompt from the server and display to user
            String prompt = "";
            try {
                prompt = br.readLine();
                if (prompt.equals(inactive_msg)) {
                    System.exit(-1);
                }

            } catch (IOException e) {
                print("Unable to read message from Server.", 1);
            }
            print(prompt, 2);

            // read the user's input and send to server
            String reply;
            if (scan.hasNextLine())
            {
                reply = scan.nextLine();
                if (reply != null && !reply.isEmpty()) {
                    pw.println(reply);
                }
            }
        }
    }

    // Continuously loops writing and reading to and from the server
    private void start_client() {

        while (connected) {
            try {
                while (scan.hasNextLine()) {
                    pw.println(scan.nextLine());
                }
            } catch (NoSuchElementException e) {
                break;
            }
        }

        try {
            client_sock.close();
        } catch (IOException e) {/* */}
    }

    // A hook that captures interrupt signals from the server
    private void init_shutdown_hook() {

        Runtime.getRuntime().addShutdownHook(new Thread() {
            @Override
            public void run() {

                connected = false;
                print("Disconnected from server.", 1);

                // try to close out everything
                try {
                    client_sock.close();
                    print("Closed client socket.", 1);
                    br.close();
                    pw.close();

                } catch (IOException e) {
                    print("Unable to close client sock.", 1);
                } catch (NullPointerException e) { /* */ }
            }
        });
    }

    // Shorten print statements to display to user
    private void print(String msg, int opt) {

        if (opt == 1) {
            System.out.println(msg);
        } else {
            System.out.print(msg);
        }
    }

    // A thread to handle communicating with server
    private class Server_Thread extends Thread {

        private BufferedReader br;

        private Server_Thread(BufferedReader reader) {
            br = reader;
        }

        @Override
        public void run() {

            String line;
            try {
                while ((line = br.readLine()) != null) {
                    print(line, 1);
                    if (line.equals(inactive_msg) || isInterrupted()){
                        break;
                    }
                }
                System.exit(-1);
            }
            catch (IOException e) { /* */ }
        }
    }

    // Main - args[0] = server ip address, args[1] = server port number
    public static void main(String[] args) {

        if (args.length != 2) {
            System.out.println("Usage: Client <Server IP Address> <Server Port Number>");
            System.exit(-1);
        }

        Client c = new Client(args[0], Integer.parseInt(args[1]));
        c.start_client();
    }
}