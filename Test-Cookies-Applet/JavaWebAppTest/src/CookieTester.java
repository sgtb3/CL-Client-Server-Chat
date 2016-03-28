/**
 * This Servlet creates a form for a client to input a string
 * value as a cookie. On submission, it creates a cookie associated
 * with that value. An expiration time limit can be set in the
 * web.xml file. Most of the code remains the same as the text parser.
 */

import java.io.IOException;
import java.io.PrintWriter;
import java.util.Date;
import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class CookieTester extends HttpServlet {

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
        final String input_string = new String(req.getParameter("input").
                getBytes("iso-8859-1"), "UTF-8");
        PrintWriter p  = resp.getWriter();

        //adjustments IOT display correctly
        req.setCharacterEncoding("UTF-8");
        resp.setCharacterEncoding("UTF-8");
        resp.setContentType("text/html");
        make_welcome(req.getHeader("Accept-Language"), p);

        //create a Cookie obj and handle the cookie information
        Cookie ck = doCookie(req, resp, p, input_string);
        if (ck != null) {
            p.println("<br>Cookie Name: "  + ck.getName());
            p.println("<br>Cookie Value: " + ck.getValue());
        }
        html_format("", 2);
    }

    private Cookie doCookie(HttpServletRequest req, HttpServletResponse resp,
                            PrintWriter p, String input) {
        
        //array to hold the cookie objects
        Cookie[] ck_arr = req.getCookies();
        Cookie ck = null;
        int ck_expir = 0;

        //retrieve the cookie if it exists
        if (ck_arr != null) {
            for (Cookie c : ck_arr) {
                if (c.getName().equals(input))
                    ck = c;
            }
        }
        
        if (ck != null) {
            p.println("<b>Retrieved Cookie.</b>");

        } else {
            //otherwise create a cookie
            ck_expir = new Integer(getServletContext().
                    getInitParameter("CookieExpirationTime"));
            
            ck = new Cookie(input, Long.toString(new Date().getTime()));

            ck.setMaxAge(ck_expir);
            ck.setPath(req.getContextPath());

            p.println("<b>Created Cookie.</b>");
            resp.addCookie(ck);
        }
        return ck;
    }

    /**
     * Display an appropriate welcome greeting
     * @param lang : The ACCEPT_LANGUAGE parameter
     * @param p    : PrintWriter obj for properly encoded output
     * @throws IOException
     */
    protected void make_welcome(String lang, PrintWriter p) 
            throws IOException {
        
        if (lang_pref(lang, "fi")){
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
     * Format the page for HTML
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