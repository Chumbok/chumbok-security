package com.chumbok.security;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.lang.Assert;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.GenericFilterBean;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.util.Collection;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

/**
 * Read authentication header or cookie in incoming HTTP request and
 * set JwtAuthenticationToken as Authentication in SecurityContext.
 */
@Slf4j
public class AuthTokenConsumerFilter extends GenericFilterBean {

    private final AuthTokenExtractor authTokenExtractor;
    private final AuthTokenParser authTokenParser;

    /**
     * AuthTokenConsumerFilter constructor with default AuthTokenExtractor.
     *
     * @param authTokenParser
     */
    public AuthTokenConsumerFilter(AuthTokenParser authTokenParser) {
        this.authTokenExtractor = new AuthTokenExtractor();
        this.authTokenParser = authTokenParser;
        Assert.notNull(authTokenParser, "authTokenParser can not be null.");
    }

    /**
     * AuthTokenConsumerFilter constructor if default authTokenExtractor need to be overridden.
     *
     * @param authTokenExtractor
     * @param authTokenParser
     */
    public AuthTokenConsumerFilter(AuthTokenExtractor authTokenExtractor, AuthTokenParser authTokenParser) {
        this.authTokenExtractor = authTokenExtractor;
        this.authTokenParser = authTokenParser;
        Assert.notNull(authTokenExtractor, "authTokenExtractor can not be null.");
        Assert.notNull(authTokenParser, "authTokenParser can not be null.");
    }

    /**
     * Overridden doFilter() from GenericFilterBean.
     *
     * @param request
     * @param response
     * @param chain
     * @throws IOException
     * @throws ServletException
     */
    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {

        if (request instanceof HttpServletRequest) {
            HttpServletRequest httpRequest = (HttpServletRequest) request;
            Optional<String> authToken = authTokenExtractor.extract(httpRequest);
            authToken.ifPresent(this::processToken);
        } else {
            log.debug("Incoming request is not HttpServletRequest. Skipping auth token is not parsed and " +
                    "authentication is NOT set in SecurityContext.");
        }

        chain.doFilter(request, response);
    }


    /**
     * Overridable processToken(String token) method.
     *
     * @param token
     */
    protected void processToken(String token) {

        Optional<Jws<Claims>> claimsJws = authTokenParser.parseClaims(token);

        if (!claimsJws.isPresent()) {
            log.debug("AuthTokenParser did not returned any claimsJws. Authentication is NOT set in SecurityContext.");
            return;
        }

        String domain = (String) claimsJws.get().getBody().get("domain");
        if (domain == null || StringUtils.isEmpty(domain)) {
            log.debug("Could not found domain in claimsJws. Authentication is NOT set in SecurityContext.");
            return;
        }

        String username = claimsJws.get().getBody().getSubject();
        if (username == null || StringUtils.isEmpty(username)) {
            log.debug("Could not found username in claimsJws. Authentication is NOT set in SecurityContext.");
            return;
        }

        List<String> scopes = claimsJws.get().getBody().get("scopes", List.class);
        if (scopes == null || scopes.isEmpty()) {
            log.debug("Could not found scopes in claimsJws. Authentication is NOT set in SecurityContext.");
            return;
        }

        String principal = domain.trim() + String.valueOf(Character.LINE_SEPARATOR) + username.trim();
        log.debug("Domain and Username found in claimsJws. Prepared principal - %s", principal);

        Collection<GrantedAuthority> authorities = scopes.stream()
                .map(authority -> new SimpleGrantedAuthority(authority))
                .collect(Collectors.toList());
        log.debug("GrantedAuthority found in claimsJws. Prepared authorities - %s", authorities);


        JwtAuthenticationToken jwtAuthenticationToken = new JwtAuthenticationToken(principal, authorities);
        SecurityContextHolder.getContext().setAuthentication(jwtAuthenticationToken);
        log.debug("JwtAuthenticationToken is successfully set in SecurityContext.");
    }
}
