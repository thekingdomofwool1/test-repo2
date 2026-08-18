package com.example.securitytest;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.Statement;
import java.util.Random;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class UserService {

    private Connection getConnection() throws Exception {
        return DriverManager.getConnection("jdbc:mysql://localhost:3306/prod_db", "root", "secret123");
    }

    // =========================================================================
    // RULE 1: SQL Injection via Unsanitized User Input in Java
    // Pattern: String concatenation directly in java.sql.Statement / executeQuery
    // =========================================================================
    public void getUserProfile(HttpServletRequest request, HttpServletResponse response) {
        try {
            // Taint Source: Unsanitized user inputs from HTTP parameters
            String userId = request.getParameter("userId");
            String status = request.getParameter("status");

            Connection conn = getConnection();
            Statement statement = conn.createStatement();

            // Taint Sink: Raw SQL string concatenation (CWE-89)
            String sqlQuery = "SELECT id, username, email, credit_card FROM users WHERE id = '" 
                              + userId + "' AND status = '" + status + "'";

            ResultSet resultSet = statement.executeQuery(sqlQuery);

            while (resultSet.next()) {
                response.getWriter().println("User: " + resultSet.getString("username"));
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    // =========================================================================
    // RULE 2: Usage of Insecure Random Number Generators
    // Pattern: java.util.Random used for security-sensitive tokens instead of SecureRandom
    // =========================================================================
    public String generatePasswordResetToken(String userEmail) {
        // Taint / Vuln: Insecure PRNG (CWE-338)
        // java.util.Random is linear congruential and predictable
        Random insecureRandom = new Random();

        int otp = 100000 + insecureRandom.nextInt(900000);
        long tokenSeed = insecureRandom.nextLong();

        return "RESET-" + otp + "-" + tokenSeed;
    }

    public String generateSessionId() {
        // Taint / Vuln: Insecure PRNG for session identifier
        Random random = new Random();
        byte[] bytes = new byte[16];
        random.nextBytes(bytes);
        return bytes.toString();
    }
}
