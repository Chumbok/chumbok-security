package com.chumbok.security.filter;

import com.chumbok.security.JwtAuthenticationToken;
import com.chumbok.security.exception.AuthTokenConsumeException;
import com.chumbok.security.properties.SecurityProperties;
import com.chumbok.security.util.AuthTokenExtractor;
import com.chumbok.security.util.AuthTokenParser;
import com.chumbok.security.util.SecurityUtil;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.impl.DefaultClaims;
import io.jsonwebtoken.impl.DefaultJws;
import io.jsonwebtoken.impl.DefaultJwsHeader;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.mockito.ArgumentCaptor;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContext;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.util.Collection;
import java.util.Collections;
import java.util.Optional;

import static org.junit.Assert.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

public class AuthTokenConsumerFilterTest {

    private final AuthTokenExtractor authTokenExtractor;
    private final AuthTokenParser authTokenParser;
    private final SecurityProperties securityProperties;
    private final SecurityUtil securityUtil;
    private final AuthTokenConsumerFilter authTokenConsumerFilter;
    private final ServletRequest servletRequest;
    private final ServletResponse servletResponse;
    private final FilterChain chain;
    @Rule
    public ExpectedException thrown = ExpectedException.none();

    public AuthTokenConsumerFilterTest() {

        this.authTokenExtractor = mock(AuthTokenExtractor.class);
        this.authTokenParser = mock(AuthTokenParser.class);
        this.securityProperties = mock(SecurityProperties.class);
        this.securityUtil = mock(SecurityUtil.class);
        this.authTokenConsumerFilter =
                new AuthTokenConsumerFilter(authTokenExtractor, authTokenParser, securityProperties, securityUtil);

        servletRequest = mock(HttpServletRequest.class);
        servletResponse = mock(ServletResponse.class);
        chain = mock(FilterChain.class);
    }

    @Test
    public void shouldNotCallAuthTokenExtractorWhenSecurityPropertiesIsNotEnabled()
            throws IOException, ServletException {

        // Given
        when(securityProperties.isEnable()).thenReturn(false);

        // When
        authTokenConsumerFilter.doFilter(servletRequest, servletResponse, chain);

        // Then
        verify(authTokenExtractor, times(0)).extract(any());
    }

    @Test
    public void shouldThrowExceptionWhenSecurityPropertiesAssertOrgWithIsNull()
            throws IOException, ServletException {

        // Given

        thrown.expect(AuthTokenConsumeException.class);
        thrown.expectMessage(AuthTokenConsumerFilter.ASSERT_ORG_MISSING_MSG);

        when(securityProperties.isEnable()).thenReturn(true);
        when(securityProperties.getAssertOrgWith()).thenReturn(null);

        // When
        authTokenConsumerFilter.doFilter(servletRequest, servletResponse, chain);

        // Then
        // Should just pass.
    }

    @Test
    public void shouldThrowExceptionWhenSecurityPropertiesAssertOrgWithIsEmpty()
            throws IOException, ServletException {

        // Given

        thrown.expect(AuthTokenConsumeException.class);
        thrown.expectMessage(AuthTokenConsumerFilter.ASSERT_ORG_MISSING_MSG);

        when(securityProperties.isEnable()).thenReturn(true);
        when(securityProperties.getAssertOrgWith()).thenReturn("");

        // When
        authTokenConsumerFilter.doFilter(servletRequest, servletResponse, chain);

        // Then
        // Should just pass.
    }

    @Test
    public void shouldThrowExceptionWhenSecurityPropertiesAssertTenantIsTrueAndAssertTenantWithIsNull()
            throws IOException, ServletException {

        // Given

        thrown.expect(AuthTokenConsumeException.class);
        thrown.expectMessage(AuthTokenConsumerFilter.ASSERT_TENANT_MISSING_MSG);

        when(securityProperties.isEnable()).thenReturn(true);
        when(securityProperties.getAssertOrgWith()).thenReturn("MyOrg");
        when(securityProperties.isAssertTenant()).thenReturn(true);
        when(securityProperties.getAssertTenantWith()).thenReturn(null);

        // When
        authTokenConsumerFilter.doFilter(servletRequest, servletResponse, chain);

        // Then
        // Should just pass.
    }

    @Test
    public void shouldThrowExceptionWhenSecurityPropertiesAssertTenantIsTrueAndAssertTenantWithIsEmpty()
            throws IOException, ServletException {

        // Given

        thrown.expect(AuthTokenConsumeException.class);
        thrown.expectMessage(AuthTokenConsumerFilter.ASSERT_TENANT_MISSING_MSG);

        when(securityProperties.isEnable()).thenReturn(true);
        when(securityProperties.getAssertOrgWith()).thenReturn("MyOrg");
        when(securityProperties.isAssertTenant()).thenReturn(true);
        when(securityProperties.getAssertTenantWith()).thenReturn("");

        // When
        authTokenConsumerFilter.doFilter(servletRequest, servletResponse, chain);

        // Then
        // Should just pass.
    }

    @Test
    public void shouldNotCallAuthTokenExtractorWhenServletRequestIsNotHttpServletRequest()
            throws IOException, ServletException {

        // Given
        ServletRequest servletRequest = mock(ServletRequest.class);

        // When
        authTokenConsumerFilter.doFilter(servletRequest, servletResponse, chain);

        // Then
        verify(authTokenExtractor, times(0)).extract(any());
    }

    @Test
    public void shouldNotCallAuthTokenParserWhenNoAccessTokenExtractedFromHttpServletRequest()
            throws IOException, ServletException {

        // Given
        when(authTokenExtractor.extract((HttpServletRequest) servletRequest)).thenReturn(Optional.empty());

        // When
        authTokenConsumerFilter.doFilter(servletRequest, servletResponse, chain);

        // Then
        verify(authTokenParser, times(0)).parseClaims(any());
    }

    @Test
    public void shouldThrowExceptionWhenNoJwsClaims() throws IOException, ServletException {

        // Given

        thrown.expect(AuthTokenConsumeException.class);
        thrown.expectMessage(AuthTokenConsumerFilter.CLAIMS_JWS_MISSING_MSG);

        when(securityProperties.isEnable()).thenReturn(true);
        when(securityProperties.getAssertOrgWith()).thenReturn("MyOrg");
        when(securityProperties.isAssertTenant()).thenReturn(true);
        when(securityProperties.getAssertTenantWith()).thenReturn("MyTenant");
        when(authTokenExtractor.extract(any())).thenReturn(Optional.of("validAuthToken"));
        when(authTokenParser.parseClaims(any())).thenReturn(Optional.empty());

        // When
        authTokenConsumerFilter.doFilter(servletRequest, servletResponse, chain);

        // Then
        // Should just pass.
    }

    @Test
    public void shouldThrowExceptionWhenJwsClaimsDoesNotHaveOrgClaim() throws IOException, ServletException {

        // Given

        thrown.expect(AuthTokenConsumeException.class);
        thrown.expectMessage(AuthTokenConsumerFilter.ORG_MISSING_CLAIMS_JWS_MSG);

        when(securityProperties.isEnable()).thenReturn(true);
        when(securityProperties.getAssertOrgWith()).thenReturn("MyOrg");
        when(securityProperties.isAssertTenant()).thenReturn(true);
        when(securityProperties.getAssertTenantWith()).thenReturn("MyTenant");
        when(authTokenExtractor.extract(any())).thenReturn(Optional.of("validAuthToken"));

        Jws<Claims> claimsJws = new DefaultJws<>(new DefaultJwsHeader(), new DefaultClaims(), "");
        when(authTokenParser.parseClaims(any())).thenReturn(Optional.of(claimsJws));

        // When
        authTokenConsumerFilter.doFilter(servletRequest, servletResponse, chain);

        // Then
        // Should just pass.
    }

    @Test
    public void shouldThrowExceptionWhenJwsClaimsDoesNotHaveTenantClaim() throws IOException, ServletException {

        // Given

        thrown.expect(AuthTokenConsumeException.class);
        thrown.expectMessage(AuthTokenConsumerFilter.TENANT_MISSING_CLAIMS_JWS_MSG);

        when(securityProperties.isEnable()).thenReturn(true);
        when(securityProperties.getAssertOrgWith()).thenReturn("MyOrg");
        when(securityProperties.isAssertTenant()).thenReturn(true);
        when(securityProperties.getAssertTenantWith()).thenReturn("MyTenant");
        when(authTokenExtractor.extract(any())).thenReturn(Optional.of("validAuthToken"));

        Claims claims = new DefaultClaims();
        claims.put("org", "MyOrg");
        Jws<Claims> claimsJws = new DefaultJws<>(new DefaultJwsHeader(), claims, "");
        when(authTokenParser.parseClaims(any())).thenReturn(Optional.of(claimsJws));

        // When
        authTokenConsumerFilter.doFilter(servletRequest, servletResponse, chain);

        // Then
        // Should just pass.
    }

    @Test
    public void shouldThrowExceptionWhenJwsClaimsDoesNotHaveUsernameClaim() throws IOException, ServletException {

        // Given

        thrown.expect(AuthTokenConsumeException.class);
        thrown.expectMessage(AuthTokenConsumerFilter.USERNAME_MISSING_CLAIMS_JWS_MSG);

        when(securityProperties.isEnable()).thenReturn(true);
        when(securityProperties.getAssertOrgWith()).thenReturn("MyOrg");
        when(securityProperties.isAssertTenant()).thenReturn(true);
        when(securityProperties.getAssertTenantWith()).thenReturn("MyTenant");
        when(authTokenExtractor.extract(any())).thenReturn(Optional.of("validAuthToken"));

        Claims claims = new DefaultClaims();
        claims.put("org", "MyOrg");
        claims.put("tenant", "MyTenant");
        Jws<Claims> claimsJws = new DefaultJws<>(new DefaultJwsHeader(), claims, "");
        when(authTokenParser.parseClaims(any())).thenReturn(Optional.of(claimsJws));

        // When
        authTokenConsumerFilter.doFilter(servletRequest, servletResponse, chain);

        // Then
        // Should just pass.
    }

    @Test
    public void shouldThrowExceptionWhenJwsClaimsDoesNotHaveScopesClaim() throws IOException, ServletException {

        // Given

        thrown.expect(AuthTokenConsumeException.class);
        thrown.expectMessage(AuthTokenConsumerFilter.SCOPES_MISSING_CLAIMS_JWS_MSG);

        when(securityProperties.isEnable()).thenReturn(true);
        when(securityProperties.getAssertOrgWith()).thenReturn("MyOrg");
        when(securityProperties.isAssertTenant()).thenReturn(true);
        when(securityProperties.getAssertTenantWith()).thenReturn("MyTenant");
        when(authTokenExtractor.extract(any())).thenReturn(Optional.of("validAuthToken"));

        Claims claims = new DefaultClaims();
        claims.put("org", "MyOrg");
        claims.put("tenant", "MyTenant");
        claims.setSubject("MyUsername");
        Jws<Claims> claimsJws = new DefaultJws<>(new DefaultJwsHeader(), claims, "");
        when(authTokenParser.parseClaims(any())).thenReturn(Optional.of(claimsJws));

        // When
        authTokenConsumerFilter.doFilter(servletRequest, servletResponse, chain);

        // Then
        // Should just pass.
    }

    @Test
    public void shouldNotSetAuthenticationInSecurityContextWhenAssertOrgWithNotMatchedWithTokenOrg()
            throws IOException, ServletException {

        // Given
        when(securityProperties.isEnable()).thenReturn(true);
        when(securityProperties.getAssertOrgWith()).thenReturn("MyOrg");
        when(authTokenExtractor.extract(any())).thenReturn(Optional.of("validAuthToken"));

        Claims claims = new DefaultClaims();
        claims.put("org", "TokenOrg");
        claims.put("tenant", "TokenTenant");
        claims.setSubject("TokenUsername");
        claims.put("scopes", Collections.singletonList("ROLE_HELLO"));
        Jws<Claims> claimsJws = new DefaultJws<>(new DefaultJwsHeader(), claims, "");
        when(authTokenParser.parseClaims(any())).thenReturn(Optional.of(claimsJws));

        SecurityContext securityContext = mock(SecurityContext.class);
        when(securityUtil.getSecurityContext()).thenReturn(securityContext);

        // When
        authTokenConsumerFilter.doFilter(servletRequest, servletResponse, chain);

        // Then
        verify(securityContext, times(0)).setAuthentication(any());
    }

    @Test
    public void shouldNotSetAuthInSecurityContextWhenSecurityPropAssertTenantIsTrueAndAssertTenantWithNotMatchedWithTokenTenant()
            throws IOException, ServletException {

        // Given
        when(securityProperties.isEnable()).thenReturn(true);
        when(securityProperties.getAssertOrgWith()).thenReturn("MyOrg");
        when(securityProperties.isAssertTenant()).thenReturn(true);
        when(securityProperties.getAssertTenantWith()).thenReturn("MyTenant");
        when(authTokenExtractor.extract(any())).thenReturn(Optional.of("validAuthToken"));

        Claims claims = new DefaultClaims();
        claims.put("org", "MyOrg");
        claims.put("tenant", "TokenTenant");
        claims.setSubject("TokenUsername");
        claims.put("scopes", Collections.singletonList("ROLE_HELLO"));
        Jws<Claims> claimsJws = new DefaultJws<>(new DefaultJwsHeader(), claims, "");
        when(authTokenParser.parseClaims(any())).thenReturn(Optional.of(claimsJws));

        SecurityContext securityContext = mock(SecurityContext.class);
        when(securityUtil.getSecurityContext()).thenReturn(securityContext);

        // When
        authTokenConsumerFilter.doFilter(servletRequest, servletResponse, chain);

        // Then
        verify(securityContext, times(0)).setAuthentication(any());
    }

    @Test
    public void shouldNotSetAuthToSecurityContextWhenSecurityContextIsNull() throws IOException, ServletException {

        // Given

        when(securityProperties.isEnable()).thenReturn(true);
        when(securityProperties.getAssertOrgWith()).thenReturn("MyOrg");
        when(securityProperties.isAssertTenant()).thenReturn(true);
        when(securityProperties.getAssertTenantWith()).thenReturn("MyTenant");
        when(authTokenExtractor.extract(any())).thenReturn(Optional.of("validAuthToken"));

        Claims claims = new DefaultClaims();
        claims.put("org", "MyOrg");
        claims.put("tenant", "MyTenant");
        claims.setSubject("MyUsername");
        claims.put("scopes", Collections.singletonList("ROLE_HELLO"));
        Jws<Claims> claimsJws = new DefaultJws<>(new DefaultJwsHeader(), claims, "");
        when(authTokenParser.parseClaims(any())).thenReturn(Optional.of(claimsJws));

        when(securityUtil.newInstance(any(), any())).thenReturn(mock(JwtAuthenticationToken.class));

        SecurityContext securityContext = mock(SecurityContext.class);
        when(securityUtil.getSecurityContext()).thenReturn(null);

        // When
        authTokenConsumerFilter.doFilter(servletRequest, servletResponse, chain);

        // Then
        verify(securityContext, times(0)).setAuthentication(any());

    }

    @Test
    public void shouldCreateJwtAuthenticationTokenAndSetToSecurityContextWhenNoValidationFails()
            throws IOException, ServletException {

        // Given

        ArgumentCaptor<String> principleCaptor = ArgumentCaptor.forClass(String.class);
        ArgumentCaptor<Collection> authoritiesCaptor = ArgumentCaptor.forClass(Collection.class);

        when(securityProperties.isEnable()).thenReturn(true);
        when(securityProperties.getAssertOrgWith()).thenReturn("MyOrg");
        when(securityProperties.isAssertTenant()).thenReturn(true);
        when(securityProperties.getAssertTenantWith()).thenReturn("MyTenant");
        when(authTokenExtractor.extract(any())).thenReturn(Optional.of("validAuthToken"));

        Claims claims = new DefaultClaims();
        claims.put("org", "MyOrg");
        claims.put("tenant", "MyTenant");
        claims.setSubject("MyUsername");
        claims.put("scopes", Collections.singletonList("ROLE_HELLO"));
        Jws<Claims> claimsJws = new DefaultJws<>(new DefaultJwsHeader(), claims, "");
        when(authTokenParser.parseClaims(any())).thenReturn(Optional.of(claimsJws));

        when(securityUtil.newInstance(any(), any())).thenReturn(mock(JwtAuthenticationToken.class));

        SecurityContext securityContext = mock(SecurityContext.class);
        when(securityUtil.getSecurityContext()).thenReturn(securityContext);

        // When
        authTokenConsumerFilter.doFilter(servletRequest, servletResponse, chain);

        // Then

        verify(securityContext, times(1)).setAuthentication(any());

        verify(securityUtil).newInstance(principleCaptor.capture(), authoritiesCaptor.capture());
        assertEquals("MyOrg" + String.valueOf(Character.LINE_SEPARATOR)
                + "MyTenant" + String.valueOf(Character.LINE_SEPARATOR) + "MyUsername", principleCaptor.getValue());
        assertEquals(Collections.singletonList(new SimpleGrantedAuthority("ROLE_HELLO")), authoritiesCaptor.getValue());
    }
}