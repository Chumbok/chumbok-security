package com.chumbok.security;

import sun.security.rsa.RSAPublicKeyImpl;

import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.PublicKey;

/**
 * EncryptionKeyUtil
 */
public class EncryptionKeyUtil {

    /**
     * Load public key from file path.
     * @param path
     * @throws RuntimeException in case any exception occurs in the process.
     * @return
     */
    public PublicKey loadPublicKey(String path) {
        try {
            byte[] keyBytes = Files.readAllBytes(Paths.get(path));
            return new RSAPublicKeyImpl(keyBytes);
        } catch (Exception ex) {
            throw new RuntimeException("Could not load PublicKey from " + path, ex);
        }
    }

}
