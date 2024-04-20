package cn.gzten.security.security;

import jakarta.servlet.*;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;

import java.io.IOException;
import java.util.List;
import java.util.Locale;
import java.util.Optional;

@Slf4j
public abstract class AbstractSecurityFilter implements Filter {

    public abstract List<AuthRule> getAuthorizationRules();

    public abstract Optional<AuthUser> getAuthUser(HttpServletRequest request);

    @Override
    public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain) throws IOException, ServletException {
        var request = (HttpServletRequest) servletRequest;
        var response = (HttpServletResponse) servletResponse;
        var a = getAuthUser(request);
        AuthUser user = AuthUser.ANONYMOUS_USER;
        if (a.isPresent()) {
            user = a.get();
        }
        request.setAttribute(AuthUser.AUTH_USER, user);

        var rules = getAuthorizationRules();
        if (rules != null && !rules.isEmpty()) {
            for (var rule : rules) {
                if (rule.matches(request.getServletPath(), request.getMethod())) {
                    if (rule.getType().equals(AuthRule.RuleType.ANONYMOUS)
                            || (rule.getType().equals(AuthRule.RuleType.AUTHENTICATED) && !user.isAnonymous())
                            || (rule.getType().equals(AuthRule.RuleType.HAS_ROLE) && matchesRole(user.getRoles(), rule.getRoles()))) {
                        filterChain.doFilter(servletRequest, servletResponse);
                        return;
                    } else {
                        response.setStatus(401);
                        try (var out = response.getWriter()){
                            out.println("Unauthorized");
                            out.flush();
                        }
                        return;
                    }
                }
            }
        }

        filterChain.doFilter(servletRequest, servletResponse);
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
