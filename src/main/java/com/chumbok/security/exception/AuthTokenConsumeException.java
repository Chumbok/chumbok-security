package com.chumbok.security.exception;

/**
 * AuthTokenConsumeException is throws when security properties is enabled and rest of the configuration is mismatched.
 */
public class AuthTokenConsumeException extends RuntimeException {

    public AuthTokenConsumeException(String message) {
        super(message);
    }
}
