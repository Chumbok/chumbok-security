package com.chumbok.security.filter;

import com.chumbok.security.JwtAuthenticationToken;
import com.chumbok.security.exception.AuthTokenConsumeException;
import com.chumbok.security.properties.SecurityProperties;
import com.chumbok.security.util.AuthTokenExtractor;
import com.chumbok.security.util.AuthTokenParser;
import com.chumbok.security.util.SecurityUtil;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.lang.Assert;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContext;
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

    public static final String ASSERT_TENANT_MISSING_MSG
            = "Attribute 'assertTenant' in securityProperties is set to true, "
            + "but Attribute 'assertTenantWith' is null or empty. Authentication is NOT set in SecurityContext.";

    public static final String ASSERT_ORG_MISSING_MSG
            = "Attribute 'assertOrgWith' in securityProperties is set to null or empty. "
            + "Authentication is NOT set in SecurityContext.";

    public static final String CLAIMS_JWS_MISSING_MSG = "AuthTokenParser did not returned any claimsJws. "
            + "Authentication is NOT set in SecurityContext.";

    public static final String NOT_HTTP_SERVLET_REQ_MSG
            = "Incoming request is not HttpServletRequest. Skipping auth token is not parsed. "
            + "Authentication is NOT set in SecurityContext.";

    public static final String SECURITY_NOT_ENABLED_MSG
            = "Attribute 'enable' in securityProperties is set to false. Authentication is NOT set in SecurityContext.";

    public static final String ORG_MISSING_CLAIMS_JWS_MSG
            = "Could not found org in claimsJws. Authentication is NOT set in SecurityContext.";

    public static final String TENANT_MISSING_CLAIMS_JWS_MSG
            = "Could not found tenant in claimsJws. Authentication is NOT set in SecurityContext.";

    public static final String USERNAME_MISSING_CLAIMS_JWS_MSG
            = "Could not found username in claimsJws. Authentication is NOT set in SecurityContext.";

    public static final String SCOPES_MISSING_CLAIMS_JWS_MSG
            = "Could not found scopes in claimsJws. Authentication is NOT set in SecurityContext.";

    public static final String ORG_NOT_MATCHED_MSG
            = "Access token claim 'org' is not matched with attribute 'assertOrgWith' in securityProperties. "
            + "Authentication is NOT set in SecurityContext.";

    public static final String TENANT_NOT_MATCHED_MSG
            = "Access token claim 'tenant' is not matched with attribute 'assertTenantWith' in securityProperties. "
            + "Authentication is NOT set in SecurityContext.";

    private final AuthTokenExtractor authTokenExtractor;
    private final AuthTokenParser authTokenParser;
    private final SecurityProperties securityProperties;
    private final SecurityUtil securityUtil;

    /**
     * AuthTokenConsumerFilter constructor with default AuthTokenExtractor.
     *
     * @param authTokenParser
     */
    public AuthTokenConsumerFilter(AuthTokenParser authTokenParser, SecurityProperties securityProperties,
                                   SecurityUtil securityUtil) {
        this.authTokenExtractor = new AuthTokenExtractor();
        this.authTokenParser = authTokenParser;
        this.securityProperties = securityProperties;
        this.securityUtil = securityUtil;
        Assert.notNull(authTokenParser, "authTokenParser can not be null.");
        Assert.notNull(securityProperties, "securityProperties can not be null.");
        Assert.notNull(securityUtil, "securityUtil can not be null.");
    }

    /**
     * AuthTokenConsumerFilter constructor if default authTokenExtractor need to be overridden.
     *
     * @param authTokenExtractor
     * @param authTokenParser
     */
    public AuthTokenConsumerFilter(AuthTokenExtractor authTokenExtractor, AuthTokenParser authTokenParser,
                                   SecurityProperties securityProperties, SecurityUtil securityUtil) {
        this.authTokenExtractor = authTokenExtractor;
        this.authTokenParser = authTokenParser;
        this.securityProperties = securityProperties;
        this.securityUtil = securityUtil;
        Assert.notNull(authTokenExtractor, "authTokenExtractor can not be null.");
        Assert.notNull(authTokenParser, "authTokenParser can not be null.");
        Assert.notNull(securityProperties, "securityProperties can not be null.");
        Assert.notNull(securityUtil, "securityUtil can not be null.");
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
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {

        if (!securityProperties.isEnable()) {
            log.info(SECURITY_NOT_ENABLED_MSG);
        } else if (securityProperties.getAssertOrgWith() == null
                || StringUtils.isEmpty(securityProperties.getAssertOrgWith())) {
            log.debug(ASSERT_ORG_MISSING_MSG);
            throw new AuthTokenConsumeException(ASSERT_ORG_MISSING_MSG);
        } else if (securityProperties.isAssertTenant() &&
                (securityProperties.getAssertTenantWith() == null ||
                        StringUtils.isEmpty(securityProperties.getAssertTenantWith()))) {
            log.debug(ASSERT_TENANT_MISSING_MSG);
            throw new AuthTokenConsumeException(ASSERT_TENANT_MISSING_MSG);
        } else if (request instanceof HttpServletRequest) {
            HttpServletRequest httpRequest = (HttpServletRequest) request;
            Optional<String> authToken = authTokenExtractor.extract(httpRequest);
            authToken.ifPresent(this::processToken);
        } else {
            log.info(NOT_HTTP_SERVLET_REQ_MSG);
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
            log.debug(CLAIMS_JWS_MISSING_MSG);
            throw new AuthTokenConsumeException(CLAIMS_JWS_MISSING_MSG);
        }

        String org = (String) claimsJws.get().getBody().get("org");
        if (org == null || StringUtils.isEmpty(org)) {
            log.debug(ORG_MISSING_CLAIMS_JWS_MSG);
            throw new AuthTokenConsumeException(ORG_MISSING_CLAIMS_JWS_MSG);
        }

        String tenant = (String) claimsJws.get().getBody().get("tenant");
        if (tenant == null || StringUtils.isEmpty(tenant)) {
            log.debug(TENANT_MISSING_CLAIMS_JWS_MSG);
            throw new AuthTokenConsumeException(TENANT_MISSING_CLAIMS_JWS_MSG);
        }

        String username = claimsJws.get().getBody().getSubject();
        if (username == null || StringUtils.isEmpty(username)) {
            log.debug(USERNAME_MISSING_CLAIMS_JWS_MSG);
            throw new AuthTokenConsumeException(USERNAME_MISSING_CLAIMS_JWS_MSG);
        }

        List<String> scopes = claimsJws.get().getBody().get("scopes", List.class);
        if (scopes == null || scopes.isEmpty()) {
            log.debug(SCOPES_MISSING_CLAIMS_JWS_MSG);
            throw new AuthTokenConsumeException(SCOPES_MISSING_CLAIMS_JWS_MSG);
        }

        if (!securityProperties.getAssertOrgWith().equals(org)) {
            log.info(ORG_NOT_MATCHED_MSG);
            return;
        }

        if (securityProperties.isAssertTenant() && !securityProperties.getAssertTenantWith().equals(tenant)) {
            log.info(TENANT_NOT_MATCHED_MSG);
            return;
        }

        String principal = org + String.valueOf(Character.LINE_SEPARATOR)
                + tenant + String.valueOf(Character.LINE_SEPARATOR)
                + username;
        log.debug("Org, Tenant and Username found in claimsJws. Prepared principal - {}", principal);

        Collection<GrantedAuthority> authorities = scopes.stream()
                .map(authority -> new SimpleGrantedAuthority(authority))
                .collect(Collectors.toList());
        log.debug("GrantedAuthority found in claimsJws. Prepared authorities - {}", authorities);


        JwtAuthenticationToken jwtAuthenticationToken = securityUtil.newInstance(principal, authorities);

        SecurityContext securityContext = securityUtil.getSecurityContext();
        if (securityContext == null) {
            log.debug("SecurityContext is null. ");
            return;
        }

        securityContext.setAuthentication(jwtAuthenticationToken);
        log.debug("JwtAuthenticationToken is successfully set in SecurityContext.");
    }
}
