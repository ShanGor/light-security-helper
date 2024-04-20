package cn.gzten.security.security;

import lombok.extern.slf4j.Slf4j;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

import static cn.gzten.security.security.AuthContext.AUTH_HEADER_ID;

@Slf4j
public abstract class AbstractReactiveSecurityFilter implements WebFilter {

    public abstract List<AuthRule> getAuthorizationRules();

    public abstract Optional<AuthUser> getAuthUser(ServerHttpRequest request);

    public static final Map<String, AuthUser> authUserMap = new ConcurrentHashMap<>();

    @Override
    public Mono<Void> filter(ServerWebExchange serverWebExchange,
                             WebFilterChain webFilterChain) {
        var requestId = UUID.randomUUID().toString();
        var request = serverWebExchange.getRequest().mutate().header(AUTH_HEADER_ID, requestId).build();
        var response = serverWebExchange.getResponse();
        var a = getAuthUser(request);
        AuthUser user = AuthUser.ANONYMOUS_USER;
        if (a.isPresent()) {
            user = a.get();
        }

        authUserMap.put(requestId, user);

        var rules = getAuthorizationRules();
        if (rules != null && !rules.isEmpty()) {
            for (var rule : rules) {
                if (rule.matches(request.getPath().toString(), request.getMethod().name())) {
                    if (rule.getType().equals(AuthRule.RuleType.ANONYMOUS)
                            || (rule.getType().equals(AuthRule.RuleType.AUTHENTICATED) && !user.isAnonymous())
                            || (rule.getType().equals(AuthRule.RuleType.HAS_ROLE) && matchesRole(user.getRoles(), rule.getRoles()))) {
                        break;
                    } else {
                        response.setRawStatusCode(401);
                        return response.setComplete();
                    }
                }
            }
        }

        return webFilterChain.filter(serverWebExchange.mutate().request(request).build())
                .thenEmpty(_v -> authUserMap.remove(requestId));
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

    public static String tryToGetHeader(String headerName, ServerHttpRequest request) {
        var key = headerName;
        var headers = request.getHeaders();

        if (headers.containsKey(key)) {
            return headers.getFirst(key);
        }
        key = key.toUpperCase(Locale.ROOT);
        if (headers.containsKey(key)) {
            return headers.getFirst(key);
        }
        key = key.toLowerCase(Locale.ROOT);
        if (headers.containsKey(key)) {
            return headers.getFirst(key);
        }
        return null;
    }
}
