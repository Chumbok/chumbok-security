package com.chumbok.security.config;

import com.chumbok.security.filter.AuthTokenConsumerFilter;
import com.chumbok.security.http.Http403ForbiddenEntryPoint;
import com.chumbok.security.properties.SecurityProperties;
import com.chumbok.security.util.AuthTokenParser;
import com.chumbok.security.util.SecurityUtil;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.preauth.AbstractPreAuthenticatedProcessingFilter;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.OrRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.Assert;
import org.springframework.web.filter.CorsFilter;

/**
 * AbstractSecurityConfig provides all required configuration.
 * <p>
 * In presence of UserDetailsService bean, it configures DaoAuthenticationProvider
 * and authProvider() also let you set any auth provider.
 * <p>
 * In presence of AuthTokenParser, auth token is extracted from HTTP request header or cookie
 * and set Authentication in SecurityContext.
 */
@Slf4j
public abstract class AbstractSecurityConfig extends WebSecurityConfigurerAdapter {

    private static final RequestMatcher PUBLIC_URLS = new OrRequestMatcher(
            new AntPathRequestMatcher("/public/*"),
            new AntPathRequestMatcher("/login"),
            new AntPathRequestMatcher("/ping"),
            new AntPathRequestMatcher("/version"));

    private AuthTokenParser authTokenParser;
    private SecurityProperties securityProperties;
    private UserDetailsService userDetailsService;
    private CorsFilter corsFilter;

    public AbstractSecurityConfig() {
        super();
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) {
        if (userDetailsService != null) {
            auth.authenticationProvider(authProvider(userDetailsService));
        } else {
            log.debug("userDetailsService bean is not set. DaoAuthenticationProvider is not set.");
        }
    }

    @Override
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }

    @Override
    public void configure(WebSecurity web) throws Exception {
        web.ignoring().requestMatchers(PUBLIC_URLS);
        log.debug("{} are ignored as PUBLIC_URLS", PUBLIC_URLS);
    }

    @Override
    protected void configure(final HttpSecurity http) throws Exception {

        log.debug("Configuring HttpSecurity - ");
        log.debug("httpBasic disabled, exceptionHandling set to Http403ForbiddenEntryPoint");
        log.debug("formLogin disabled, logout disabled.");
        log.debug("sessionCreationPolicy set to STATELESS.");

        http.httpBasic().disable()
                .headers().frameOptions().sameOrigin()
                .and()
                .csrf().csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
                .and()

                .exceptionHandling().authenticationEntryPoint(new Http403ForbiddenEntryPoint())
                .and()

                .formLogin().disable()
                .logout().disable()

                .sessionManagement()
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS);

        if (authTokenParser == null) {
            log.debug("authTokenParser bean is NOT set. AuthTokenConsumerFilter is NOT set in Filter chain.");
        }

        if (securityProperties == null) {
            log.debug("securityProperties bean is NOT set. AuthTokenConsumerFilter is NOT set in Filter chain.");
        }

        SecurityUtil securityUtil = securityUtil();
        if (securityUtil == null) {
            log.debug("securityUtil bean is NOT set. AuthTokenConsumerFilter is NOT set in Filter chain.");
        }

        if (authTokenParser != null && securityProperties != null && securityUtil != null) {
            http.addFilterBefore(new AuthTokenConsumerFilter(authTokenParser, securityProperties, securityUtil),
                    AbstractPreAuthenticatedProcessingFilter.class);
            log.debug("authTokenParser, securityProperties and securityUtil bean is set. " +
                    "AuthTokenConsumerFilter is set in Filter chain before AbstractPreAuthenticatedProcessingFilter");
        }

        if (corsFilter != null) {
            http.addFilterBefore(corsFilter, UsernamePasswordAuthenticationFilter.class);
        }


        http.authorizeRequests().anyRequest().authenticated();

        log.debug("Csrf is ignored for /login, /logout, /logout and /refresh.");
        http.csrf().ignoringAntMatchers("/login");
        http.csrf().ignoringAntMatchers("/logout");
        http.csrf().ignoringAntMatchers("/refresh");

    }

    /**
     * Allows to set UserDetailsService in DaoAuthenticationProvider.
     *
     * @param userDetailsService
     * @return
     */
    protected AuthenticationProvider authProvider(UserDetailsService userDetailsService) {
        DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
        provider.setUserDetailsService(userDetailsService);
        provider.setPasswordEncoder(passwordEncoder());
        provider.setForcePrincipalAsString(true);
        return provider;
    }

    /**
     * Allows to override PasswordEncoder.
     * @return
     */
    protected PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    /**
     * Allows to override SecurityUtil.
     *
     * @return
     */
    protected SecurityUtil securityUtil() {
        return new SecurityUtil();
    }

    /**
     * Allows to set UserDetailsService in DaoAuthenticationProvider.
     *
     * @param userDetailsService
     */
    protected void setUserDetailsService(UserDetailsService userDetailsService) {
        Assert.notNull(userDetailsService, "userDetailsService cannot be null");
        this.userDetailsService = userDetailsService;
    }

    /**
     * Allow to set AuthTokenParser.
     *
     * @param authTokenParser
     */
    protected void setAuthTokenParser(AuthTokenParser authTokenParser) {
        Assert.notNull(authTokenParser, "authTokenParser cannot be null");
        this.authTokenParser = authTokenParser;
    }

    /**
     * Allow to set SecurityProperties.
     *
     * @param securityProperties
     */
    protected void setSecurityProperties(SecurityProperties securityProperties) {
        Assert.notNull(securityProperties, "securityProperties cannot be null");
        this.securityProperties = securityProperties;
    }

    /**
     * Allow to set CorsFilter.
     *
     * @param corsFilters
     */
    protected void setCorsFilters(CorsFilter corsFilters) {
        Assert.notNull(corsFilters, "corsFilters cannot be null");
        this.corsFilter = corsFilters;
    }

}
