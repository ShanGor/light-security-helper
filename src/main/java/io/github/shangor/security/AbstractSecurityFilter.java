package io.github.shangor.security;

import io.micrometer.common.util.StringUtils;
import jakarta.servlet.*;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;

import java.io.IOException;
import java.util.List;
import java.util.Locale;
import java.util.Optional;

@Slf4j
public abstract class AbstractSecurityFilter extends FilterCommon implements Filter {

    protected abstract Optional<AuthUser> getAuthUser(HttpServletRequest request);

    @Override
    public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain) throws IOException, ServletException {
        var request = (HttpServletRequest) servletRequest;
        var response = (HttpServletResponse) servletResponse;
        AuthUser user = AuthUser.ANONYMOUS_USER;
        try {
            var a = getAuthUser(request);
            if (a.isPresent()) {
                user = a.get();
            }
            request.setAttribute(AuthUser.AUTH_USER, user);
        } catch (Exception e) {
            returnWith(401, e.getMessage(), response);
            return;
        }

        var rules = getAuthorizationRules();
        if (rules != null && !rules.isEmpty()) {
            for (var rule : rules) {
                if (rule.matches(request.getServletPath(), request.getMethod())) {
                    if (rule.getType().equals(AuthRule.RuleType.ANONYMOUS)
                            || (rule.getType().equals(AuthRule.RuleType.AUTHENTICATED) && !user.isAnonymous())
                            || (rule.getType().equals(AuthRule.RuleType.HAS_ROLE) && matchesRole(user.getRoles(), rule.getRoles()))) {
                        break;
                    } else {
                        returnWith(401, "Current action is not authorized!", response);
                        return;
                    }
                }
            }
        }

        filterChain.doFilter(servletRequest, servletResponse);
    }

    public static final void returnWith(final int status, final String message, final HttpServletResponse response) {
        response.setStatus(status);
        if (StringUtils.isBlank(message)) {
            return;
        }

        try (var out = response.getWriter()){
            out.println(message);
            out.flush();
        } catch (IOException e) {
            log.error("Failed to write response {}", e.getMessage());
        }
    }

    public static boolean matchesRole(List<String> roles, List<String> orRoles) {
        if (roles == null || roles.isEmpty() || orRoles == null || orRoles.isEmpty()) {
            return false;
        }
        for (var role : roles) {
            if (orRoles.contains(role)) {
                return true;
            }
        }
        return false;
    }

    public static String tryToGetHeader(String headerName, HttpServletRequest request) {
        var key = headerName;
        if (request.getHeader(key) != null) {
            return request.getHeader(key);
        }
        key = key.toUpperCase(Locale.ROOT);
        if (request.getHeader(key) != null) {
            return request.getHeader(key);
        }
        key = key.toLowerCase(Locale.ROOT);
        return request.getHeader(key);
    }
}
