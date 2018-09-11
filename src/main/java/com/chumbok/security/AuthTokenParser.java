package com.chumbok.security;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.SignatureException;
import io.jsonwebtoken.UnsupportedJwtException;
import io.jsonwebtoken.lang.Assert;
import lombok.extern.slf4j.Slf4j;

import java.security.PublicKey;
import java.util.Optional;

/**
 * Parse authentication token signed with private key.
 */
@Slf4j
public class AuthTokenParser {

    private final PublicKey tokenSigningPublicKey;

    /**
     * AuthTokenParser constructor with token signing public key.
     *
     * @param tokenSigningPublicKey
     */
    public AuthTokenParser(PublicKey tokenSigningPublicKey) {
        Assert.notNull(tokenSigningPublicKey, "tokenSigningPublicKey can not be null.");
        this.tokenSigningPublicKey = tokenSigningPublicKey;
    }

    /**
     * Parses and validates JWT Token signature.
     *
     * @param token
     * @return JWS Claims
     */
    public Optional<Jws<Claims>> parseClaims(String token) {

        try {
            return Optional.of(Jwts.parser()
                    .setSigningKey(tokenSigningPublicKey)
                    .parseClaimsJws(token));
        } catch (UnsupportedJwtException | MalformedJwtException | IllegalArgumentException | SignatureException ex) {
            log.error("Invalid JWT Token", ex);
        } catch (ExpiredJwtException expiredEx) {
            log.info("JWT Token is expired", expiredEx);
        }

        return Optional.empty();
    }


}
