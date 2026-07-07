/*
 * PaymentService.java
 *
 * NOTE:
 * This file is an intentionally insecure fixture for testing
 * static analysis (SAST) tooling.
 *
 * Methods contain placeholders only. Replace TODO sections
 * with language-specific fixtures if testing individual rules.
 */

package com.example.payment;

import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Random;

public class PaymentService {

    // --------------------------------------------------------------------
    // Hardcoded Secrets
    // --------------------------------------------------------------------

    private static final String PAYMENT_API_KEY =
        "secret_api_key_9fK3mN7qR2vT8wXz0pL5cB1hJ4dY6gA3";

    private static final String AWS_ACCESS_KEY = "AKIAVK7QMXJ3PD9LZRNT";

    private static final String AWS_SECRET =
        "Hp3vQzL8mX2wR9tNcF6jB1aS4dG7eK0yU5oI3uV8";

    private static final String DB_PASSWORD = "Tr0ub4dor&Finance2024";

    private static final String JWT_SECRET = "super-secret-jwt-signing-key";

    // --------------------------------------------------------------------
    // Weak Cryptography
    // --------------------------------------------------------------------

    public String hashCardNumber(String cardNumber) throws Exception {
        // Rule:
        // weak-crypto-md5

        MessageDigest md = MessageDigest.getInstance("MD5");

        // TODO:
        // md.digest(...)

        return "<fixture>";
    }

    public String checksum(byte[] payload) throws Exception {
        // Rule:
        // weak-crypto-sha1

        MessageDigest sha1 = MessageDigest.getInstance("SHA-1");

        return "<fixture>";
    }

    // --------------------------------------------------------------------
    // Weak Random
    // --------------------------------------------------------------------

    public String generateOtp() {
        // Rule:
        // weak-random

        Random random = new Random();

        return "<fixture>";
    }

    public String secureOtp() {
        SecureRandom random = new SecureRandom();

        return "<fixture>";
    }

    // --------------------------------------------------------------------
    // SQL Injection
    // --------------------------------------------------------------------

    public void getTransaction(String referenceId) {
        // Rule:
        // sql-injection

        String sql =
            "SELECT * FROM transactions WHERE id='" + referenceId + "'";

        // TODO:
        // execute(sql)
    }

    // --------------------------------------------------------------------
    // Command Injection
    // --------------------------------------------------------------------

    public void reconcile(String filename) {
        // Rule:
        // command-injection

        String command = "python reconcile.py --batch " + filename;

        // TODO:
        // Runtime.getRuntime().exec(command);
    }

    // --------------------------------------------------------------------
    // Path Traversal
    // --------------------------------------------------------------------

    public void loadReceipt(String filename) {
        // Rule:
        // path-traversal

        String path = "/payments/" + filename;

        // TODO:
        // Files.readAllBytes(...)
    }

    // --------------------------------------------------------------------
    // XXE
    // --------------------------------------------------------------------

    public void parseXml(byte[] xml) {
        // Rule:
        // xxe
        // TODO:
        // configure XML parser with
        // entity expansion enabled
    }

    // --------------------------------------------------------------------
    // Insecure Deserialization
    // --------------------------------------------------------------------

    public void restoreSession(byte[] data) {
        // Rule:
        // insecure-deserialization
        // TODO:
        // ObjectInputStream.readObject()
    }

    // --------------------------------------------------------------------
    // TLS
    // --------------------------------------------------------------------

    public void connectLegacyServer() {
        // Rule:
        // tls-verification-disabled
        // TODO:
        // Trust-all certificates
    }

    // --------------------------------------------------------------------
    // SSRF
    // --------------------------------------------------------------------

    public void fetchRemoteInvoice(String url) {
        // Rule:
        // ssrf
        // TODO:
        // openConnection(url)
    }

    // --------------------------------------------------------------------
    // Open Redirect
    // --------------------------------------------------------------------

    public String redirect(String destination) {
        // Rule:
        // open-redirect

        return destination;
    }

    // --------------------------------------------------------------------
    // Debug
    // --------------------------------------------------------------------

    public static final boolean DEBUG = true;

    public static final boolean ENABLE_STACKTRACE = true;

    public static final String ALLOWED_ORIGINS = "*";

    public static final boolean COOKIE_SECURE = false;

    public static final boolean CSRF_ENABLED = false;
}
