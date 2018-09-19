package com.chumbok.security.util;

import com.chumbok.testable.common.UrlUtil;
import lombok.extern.slf4j.Slf4j;
import org.springframework.util.StringUtils;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import java.util.Enumeration;
import java.util.Optional;

/**
 * Extract Auth token from HTTP header or Cookie.
 */
@Slf4j
public class AuthTokenExtractor {

    private static final String AUTH_HEADER_NAME = "Authorization";
    private static final String HEADER_SCHEMA = "Bearer";
    private static final String AUTH_COOKIE_NAME = "Authorization";

    private final UrlUtil urlUtil = new UrlUtil();

    /**
     * Extract auth token from HttpServletRequest.
     * @param httpRequest
     * @return Auth token as Optional String.
     */
    public Optional<String> extract(HttpServletRequest httpRequest) {

        Optional<String> authToken = getAuthTokenFromHeader(AUTH_HEADER_NAME, httpRequest);

        if (!authToken.isPresent()) {
            log.debug("Auth token not found in httpRequest header.");
            authToken = getAuthTokenFromCookie(AUTH_COOKIE_NAME, httpRequest);
        }

        if (!authToken.isPresent()) {
            log.debug("Auth token not found in httpRequest cookie either.");
            return Optional.empty();
        }

        String token = authToken.get();
        token = urlUtil.utf8Decode(token);

        if (token.startsWith(HEADER_SCHEMA)) {
            token = token.substring(HEADER_SCHEMA.length());
        }

        token = token.trim();

        if (StringUtils.isEmpty(token)) {
            log.debug("Auth token is empty.");
            return Optional.empty();
        }

        return Optional.of(token);

    }

    private Optional<String> getAuthTokenFromHeader(String headerName, HttpServletRequest httpRequest) {

        Enumeration<String> headerNames = httpRequest.getHeaderNames();

        while (headerNames.hasMoreElements()) {
            String header = headerNames.nextElement();
            if (headerName.equalsIgnoreCase(header)) {
                return Optional.ofNullable(httpRequest.getHeader(header));
            }
        }

        return Optional.empty();
    }

    private Optional<String> getAuthTokenFromCookie(String headerName, HttpServletRequest httpRequest) {

        Cookie[] cookies = httpRequest.getCookies() != null ? httpRequest.getCookies() : new Cookie[0];

        for (Cookie cookie : cookies) {
            if (headerName.equalsIgnoreCase(cookie.getName())) {
                return Optional.ofNullable(cookie.getValue());
            }
        }

        return Optional.empty();
    }


}
