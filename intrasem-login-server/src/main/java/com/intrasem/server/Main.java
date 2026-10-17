package com.intrasem.server;

import io.javalin.Javalin;
import io.javalin.http.Context;
import org.mindrot.jbcrypt.BCrypt;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.Map;

/**
 * Intrasem login server.
 *
 * The desktop app sends:  { "table_name": "administrator", "username": "...", "password": "..." }
 *
 *   - Username or password wrong  -> "Wrong credentials." and the failed attempt is recorded
 *                                    (3 wrong passwords = account locked for 10 minutes).
 *   - Everything correct          -> the server returns the database details to the app.
 *
 * The database details are kept in Render ENVIRONMENT VARIABLES (set once in the Render dashboard):
 *   DB_URL         jdbc:postgresql://YOUR-NEON-HOST/YOUR-DB-NAME?sslmode=require
 *   AUTH_DB_USER   database user the SERVER uses to check logins (never sent to anyone)
 *   AUTH_DB_PASS   its password
 *   APP_DB_USER    database user that is SENT to the desktop app after a correct login
 *   APP_DB_PASS    its password
 *
 * For now you may use the same user and password for both pairs. Later, when you create a database
 * user that only has access to the tables the admins need, put it in APP_DB_USER / APP_DB_PASS.
 * Nothing else needs to change.
 */
public class Main {

    /** The name of the column that holds the username, and (if the table has one) the school column. */
    private record Table(String nameCol, String schoolCol) {}

    // Table names can't be sent to the database as "?" values, so the server ONLY accepts these exact
    // names. Anything else is rejected. Both tables need the columns: pass_word, failed_attempts,
    // locked_until, status.
    // "teachingandexams" is the central admin table (it has no school column).
    private static final Map<String, Table> ALLOWED_TABLES = Map.of(
            "administrator", new Table("admin_name", "school"),
            "teachingandexams", new Table("admin_name", null)
    );

    private static final int MAX_ATTEMPTS = 3;
    private static final int LOCK_MINUTES = 10;
    private static final String WRONG = "Wrong credentials.";

    // Used so that an unknown username takes as long to answer as a wrong password.
    private static final String DUMMY_HASH = BCrypt.hashpw("not-a-real-password", BCrypt.gensalt());

    public static void main(String[] args) {
        // Stop with a clear message if a setting is missing.
        for (String name : new String[]{"DB_URL", "AUTH_DB_USER", "AUTH_DB_PASS", "APP_DB_USER", "APP_DB_PASS"}) {
            env(name);
        }

        int port = Integer.parseInt(System.getenv().getOrDefault("PORT", "8080"));
        Javalin app = Javalin.create().start(port);

        app.get("/health", ctx -> ctx.result("ok"));
        app.post("/login", Main::login);

        // Never show database error details to the app.
        app.exception(SQLException.class, (e, ctx) -> {
            e.printStackTrace();
            ctx.status(500).json(Map.of("error", "Server error. Please try again."));
        });
    }

    private static void login(Context ctx) throws SQLException {
        ctx.header("Cache-Control", "no-store");

        @SuppressWarnings("unchecked")
        Map<String, Object> body = ctx.bodyAsClass(Map.class);
        String tableName = text(body.get("table_name")).trim();
        String username = text(body.get("username")).trim();
        String password = text(body.get("password"));

        Table t = ALLOWED_TABLES.get(tableName);
        if (t == null) {
            fail(ctx, 400, "Invalid request.");
            return;
        }
        if (username.isEmpty() || password.isEmpty()) {
            fail(ctx, 400, "Username and password are required.");
            return;
        }

        // tableName and the column names come from the allowed list above, never straight from the user.
        String schoolExpr = t.schoolCol() == null ? "'' AS school" : t.schoolCol() + " AS school";
        String where = " WHERE LOWER(" + t.nameCol() + ") = LOWER(?)";
        String select = "SELECT pass_word, failed_attempts, status, " + schoolExpr + ", "
                + "(locked_until IS NOT NULL AND locked_until > NOW()) AS is_locked, "
                + "(locked_until IS NOT NULL AND locked_until <= NOW()) AS lock_expired "
                + "FROM " + tableName + where;

        try (Connection c = DriverManager.getConnection(env("DB_URL"), env("AUTH_DB_USER"), env("AUTH_DB_PASS"))) {

            String storedHash = null, status = null, school = null;
            int failed = 0;
            boolean found = false, isLocked = false, lockExpired = false;

            try (PreparedStatement ps = c.prepareStatement(select)) {
                ps.setString(1, username);
                try (ResultSet rs = ps.executeQuery()) {
                    if (rs.next()) {
                        found = true;
                        storedHash = rs.getString("pass_word");
                        status = rs.getString("status");
                        school = rs.getString("school");
                        failed = rs.getInt("failed_attempts");
                        isLocked = rs.getBoolean("is_locked");
                        lockExpired = rs.getBoolean("lock_expired");
                    }
                }
            }

            // 1. No such user. Same answer as a wrong password, so nobody can find out which usernames exist.
            if (!found) {
                BCrypt.checkpw(password, DUMMY_HASH);
                fail(ctx, 401, WRONG);
                return;
            }

            // 2. Account is locked.
            if (isLocked) {
                fail(ctx, 423, "Account is locked, please try again later.");
                return;
            }

            // 3. Wrong password: record the failed attempt.
            if (!passwordMatches(password, storedHash)) {
                int attempts = (lockExpired ? 0 : failed) + 1;   // counting starts again after a lock has expired
                if (attempts >= MAX_ATTEMPTS) {
                    run(c, "UPDATE " + tableName + " SET failed_attempts = ?, locked_until = NOW() + INTERVAL '"
                            + LOCK_MINUTES + " minutes'" + where, MAX_ATTEMPTS, username);
                    fail(ctx, 423, "Account locked due to multiple failed attempts. Try again after "
                            + LOCK_MINUTES + " minutes.");
                } else {
                    run(c, "UPDATE " + tableName + " SET failed_attempts = ?, locked_until = NULL" + where,
                            attempts, username);
                    
                    fail(ctx, 401, WRONG + " Attempt " + attempts + " of " + MAX_ATTEMPTS + ".");
                }
                return;
            }

            // 4. Correct password, but the account has been deactivated: no database details.
            if (status != null && status.equalsIgnoreCase("Inactive")) {
                fail(ctx, 403, "Account was deactivated. Please contact the support team.");
                return;
            }

            // 5. Correct: clear the failed attempts (nothing else) and return the database details.
            run(c, "UPDATE " + tableName + " SET failed_attempts = 0, locked_until = NULL" + where, username);

            ctx.json(Map.of(
                    "db_url", env("DB_URL"),
                    "db_user", env("APP_DB_USER"),
                    "db_password", env("APP_DB_PASS"),
                    "school", school == null ? "" : school.trim()));
        }
    }

    // ---------------- small helpers ----------------

    private static boolean passwordMatches(String plain, String hash) {
        if (hash == null || hash.isEmpty()) {
            return false;
        }
        if (hash.startsWith("$2y$")) {            // hashes made by PHP start with $2y$; same algorithm
            hash = "$2a$" + hash.substring(4);
        }
        try {
            return BCrypt.checkpw(plain, hash);
        } catch (IllegalArgumentException e) {    // stored value is not a valid BCrypt hash
            return false;
        }
    }

    private static void run(Connection c, String sql, Object... params) throws SQLException {
        try (PreparedStatement ps = c.prepareStatement(sql)) {
            for (int i = 0; i < params.length; i++) {
                ps.setObject(i + 1, params[i]);
            }
            ps.executeUpdate();
        }
    }

    private static String env(String name) {
        String v = System.getenv(name);
        if (v == null || v.isBlank()) {
            throw new IllegalStateException("Missing environment variable: " + name);
        }
        return v;
    }

    private static String text(Object o) {
        return o == null ? "" : o.toString();
    }

    private static void fail(Context ctx, int status, String message) {
        ctx.status(status).json(Map.of("error", message));
    }
}
