package com.chumbok.security.util;

import sun.security.rsa.RSAPrivateCrtKeyImpl;
import sun.security.rsa.RSAPublicKeyImpl;

import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.PrivateKey;
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
            byte[] keyBytes = getBytes(path);
            return new RSAPublicKeyImpl(keyBytes);
        } catch (Exception ex) {
            throw new RuntimeException("Could not load PublicKey from " + path, ex);
        }
    }

    /**
     * Load private key from file path.
     *
     * @param path
     * @return
     * @throws RuntimeException in case any exception occurs in the process.
     */
    public PrivateKey loadPrivateKey(String path) {
        try {
            byte[] keyBytes = getBytes(path);
            return RSAPrivateCrtKeyImpl.newKey(keyBytes);
        } catch (Exception ex) {
            throw new RuntimeException("Could not load PrivateKey from " + path, ex);
        }
    }

    private byte[] getBytes(String pathString) throws Exception {
        Path path;
        if (pathString.startsWith("classpath:")) {
            String originalPath = pathString.substring(10);
            URL url = getClass().getClassLoader().getResource(originalPath);
            if (url == null) {
                throw new RuntimeException("Could not load PublicKey from " + pathString);
            }
            path = Paths.get(url.toURI());
        } else {
            path = Paths.get(pathString);
        }
        return Files.readAllBytes(path);
    }
}
