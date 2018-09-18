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
    private final SecurityProperties securityProperties;

    /**
     * AuthTokenConsumerFilter constructor with default AuthTokenExtractor.
     *
     * @param authTokenParser
     */
    public AuthTokenConsumerFilter(AuthTokenParser authTokenParser, SecurityProperties securityProperties) {
        this.authTokenExtractor = new AuthTokenExtractor();
        this.authTokenParser = authTokenParser;
        this.securityProperties = securityProperties;
        Assert.notNull(authTokenParser, "authTokenParser can not be null.");
        Assert.notNull(securityProperties, "securityProperties can not be null.");
    }

    /**
     * AuthTokenConsumerFilter constructor if default authTokenExtractor need to be overridden.
     *
     * @param authTokenExtractor
     * @param authTokenParser
     */
    public AuthTokenConsumerFilter(AuthTokenExtractor authTokenExtractor, AuthTokenParser authTokenParser,
                                   SecurityProperties securityProperties) {
        this.authTokenExtractor = authTokenExtractor;
        this.authTokenParser = authTokenParser;
        this.securityProperties = securityProperties;
        Assert.notNull(authTokenExtractor, "authTokenExtractor can not be null.");
        Assert.notNull(authTokenParser, "authTokenParser can not be null.");
        Assert.notNull(securityProperties, "securityProperties can not be null.");
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

        String org = (String) claimsJws.get().getBody().get("org");
        if (org == null || StringUtils.isEmpty(org)) {
            log.debug("Could not found org in claimsJws. Authentication is NOT set in SecurityContext.");
            return;
        }

        String tenant = (String) claimsJws.get().getBody().get("tenant");
        if (org == null || StringUtils.isEmpty(org)) {
            log.debug("Could not found tenant in claimsJws. Authentication is NOT set in SecurityContext.");
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

        if (!securityProperties.isEnable()) {
            log.debug("Attribute 'enable' in securityProperties is set to false. "
                    + "Authentication is NOT set in SecurityContext.");
            return;
        }

        if (securityProperties.getAssertOrgWith() == null || StringUtils.isEmpty(securityProperties.getAssertOrgWith())) {
            log.debug("Attribute 'assertOrgWith' in securityProperties is set to null or empty. "
                    + "Authentication is NOT set in SecurityContext.");
            return;
        }

        if (!securityProperties.getAssertOrgWith().equals(org)) {
            log.debug("Access token claim 'org' is not matched with attribute 'assertOrgWith' in securityProperties. "
                    + "Authentication is NOT set in SecurityContext.");
            return;
        }

        if(securityProperties.isAssertTenant() &&
                (securityProperties.getAssertTenantWith() == null ||
                        StringUtils.isEmpty(securityProperties.getAssertTenantWith()))) {
            log.debug("Attribute 'assertTenant' in securityProperties is set to true, but Attribute 'assertTenantWith' "
                    + "is null or empty. Authentication is NOT set in SecurityContext.");
            return;
        }

        if (securityProperties.isAssertTenant() && !securityProperties.getAssertTenantWith().equals(tenant)) {
            log.debug("Access token claim 'tenant' is not matched with attribute 'assertTenantWith' in "
                    + "securityProperties. Authentication is NOT set in SecurityContext.");
            return;
        }

        String principal = org.trim() + String.valueOf(Character.LINE_SEPARATOR)
                + tenant.trim() + String.valueOf(Character.LINE_SEPARATOR)
                + username.trim();
        log.debug("Org, Tenant and Username found in claimsJws. Prepared principal - %s", principal);

        Collection<GrantedAuthority> authorities = scopes.stream()
                .map(authority -> new SimpleGrantedAuthority(authority))
                .collect(Collectors.toList());
        log.debug("GrantedAuthority found in claimsJws. Prepared authorities - %s", authorities);


        JwtAuthenticationToken jwtAuthenticationToken = new JwtAuthenticationToken(principal, authorities);
        SecurityContextHolder.getContext().setAuthentication(jwtAuthenticationToken);
        log.debug("JwtAuthenticationToken is successfully set in SecurityContext.");
    }
}
