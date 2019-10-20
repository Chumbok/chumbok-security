package com.chumbok.security.config;

import java.util.Arrays;
import java.util.HashSet;
import javax.servlet.http.HttpServletRequest;
import org.springframework.security.web.util.matcher.RequestMatcher;

public class CsrfRequestMatcher implements RequestMatcher {

    /**
     * Http header that indicate that request is coming from the Gateway.
     */
    private static final String GATEWAY_REQUEST_HEADER = "X-Forwarded-Prefix";

    private final HashSet<String> allowedMethods = new HashSet<>(
        Arrays.asList("GET", "HEAD", "TRACE", "OPTIONS"));

    @Override
    public boolean matches(HttpServletRequest request) {

        if (!isRequestFromTheGateway(request)) {
            return false;
        }

        return !this.allowedMethods.contains(request.getMethod());
    }

    private boolean isRequestFromTheGateway(HttpServletRequest request) {
        return request.getHeader(GATEWAY_REQUEST_HEADER) != null;
    }
}
