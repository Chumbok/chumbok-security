package com.chumbok.security;

import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

import java.security.PublicKey;

import static org.junit.Assert.assertNotNull;

public class EncryptionKeyUtilTest {

    @Rule
    public ExpectedException thrown = ExpectedException.none();

    @Test
    public void shouldLoadPublicKeyFromClasspath() {

        // Given
        EncryptionKeyUtil encryptionKeyUtil = new EncryptionKeyUtil();

        // When
        PublicKey publicKey = encryptionKeyUtil.loadPublicKey("classpath:public_key.der");

        // Then
        assertNotNull(publicKey);
    }

    @Test
    public void shouldThrowExceptionIfPublicKeyNotExistInClasspath() {

        // Given
        thrown.expect(RuntimeException.class);
        thrown.expectMessage("Could not load PublicKey from classpath:non_exist_public_key.der");

        EncryptionKeyUtil encryptionKeyUtil = new EncryptionKeyUtil();

        // When
        encryptionKeyUtil.loadPublicKey("classpath:non_exist_public_key.der");

        // Then
        // Expects to pass
    }

}