/**
 * This simple Java Servlet parses a string in order to determine
 * if the UTF-8 encoded text is alphanumeric. It displays a welcome
 * message in various languages depending on the language preferences
 * of the client. It also displays the length in characters (the code
 * points of UTF-8), bytes, and a hex representation.
 */

import java.io.IOException;
import java.io.PrintWriter;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class ParserServlet extends HttpServlet {

    /**
     * This function handles a POST request
     * @param req  : Client request
     * @param resp : Server response
     * @throws ServletException
     * @throws IOException
     */
    @Override
    protected void doPost(HttpServletRequest req, HttpServletResponse resp)
            throws ServletException, IOException {
        
        //set internal encoding
        System.setProperty("file.encoding","UTF-8");

        //UTF-8 encode the POST request
        final String input_string;
        input_string = new String(req.getParameter("input").
                getBytes("iso-8859-1"), "UTF-8");

        //adjustments IOT display correctly
        req.setCharacterEncoding("UTF-8");
        resp.setCharacterEncoding("UTF-8");
        resp.setContentType("text/html");

        html_format("Input Parser", 1);
        PrintWriter p = resp.getWriter();
        make_welcome(req.getHeader("Accept-Language"), p);
        parse_input(input_string, p);
        html_format("", 2);
    }

    /**
     * Parse the given string.
     * @param input : UTF-8 encoded string
     * @param p     : PrintWriter obj for properly encoded output
     * @throws IOException
     */
    protected void parse_input(final String input, PrintWriter p) 
            throws IOException {
        
        // regex matches alphanumeric unicode characters
        boolean re_match = input.matches("^[\\p{L}0-9]*$");
        int code_points  = input.codePointCount(0, input.length());
        byte[] byte_arr  = input.getBytes("UTF-8");
        StringBuilder sb = new StringBuilder();

        // display string in hex notation
        for (byte b : byte_arr) {
            sb.append(Integer.toHexString(b & 0xFF).toUpperCase()).append(" ");
        }

        p.println("<p><b>Input: </b>" + input);
        p.println("<p><b>String length in bytes: </b>" + byte_arr.length);
        p.println("<p><b>String length in characters (UTF-8 code points)</b>: " + code_points);
        p.print("<p><b>String (UTF-8 hex encoded): </b>" + sb.toString());

        if (code_points == 0 || !re_match) {
            p.println("<p><b>Input is not alphanumeric.</b>");
        } else {
            p.println("<p><b>Input is alphanumeric.</b>");
        }
    }

    /**
     * Display an appropriate welcome greeting
     * @param lang : The ACCEPT_LANGUAGE parameter
     * @param p    : PrintWriter obj for properly encoded output
     * @throws IOException
     */
    protected void make_welcome(String lang, PrintWriter p) throws IOException {
        
        if (lang_pref(lang, "fi")) {
            p.println("<center><h1> Tervetuloa! </h1></center>");
        } else if (lang_pref(lang, "ko")) {
            p.println("<center><h1> 환영! </h1></center>");
        } else if (lang_pref(lang, "fr")) {
            p.println("<center><h1> Bienvenue! </h1></center>");
        } else if (lang_pref(lang, "de")) {
            p.println("<center><h1> Willkommen! </h1></center>");
        } else {
            p.println("<center><h1> Welcome! </h1></center>");
        }
    }

    /**
     * Formats the page for HTML
     * @param text   : Title tag
     * @param option : 1 for opening tags, 2 for closing
     */
    protected void html_format(String text, int option) {
        
        if (option == 1) {
            print("<html>\n<head>\n<title>" + text + "</title>\n");
            print("</head>\n<body>");
        } else if (option == 2) {
            print("</body>\n</html>");
        }
    }

    // Shortens system print statements
    protected void print(String text) {
        System.out.println(text);
    }

    // Shorten calls to contains() 
    protected boolean lang_pref(String lang1, String lang2) {
        return lang1.toLowerCase().contains(lang2.toLowerCase());
    }
}