package io.github.shangor.security;

import io.micrometer.common.util.StringUtils;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

@Slf4j
public abstract class AbstractReactiveSecurityFilter extends FilterCommon implements WebFilter {

    public static final Map<String, AuthUser> authUserMap = new ConcurrentHashMap<>();

    protected abstract Optional<AuthUser> getAuthUser(ServerHttpRequest request);

    @Override
    public Mono<Void> filter(ServerWebExchange serverWebExchange,
                             WebFilterChain webFilterChain) {

        var request = serverWebExchange.getRequest();
        var requestId = request.getId();
        var response = serverWebExchange.getResponse();
        AuthUser user = AuthUser.ANONYMOUS_USER;
        try {
            var a = getAuthUser(request);
            if (a.isPresent()) {
                user = a.get();
            }
        } catch (Exception e) {
            return returnWith(401, e.getMessage(), response);
        }
        authUserMap.put(requestId, user);
        response.beforeCommit(() -> {
            authUserMap.remove(requestId);
            return Mono.empty();
        });

        var rules = getAuthorizationRules();
        if (rules != null && !rules.isEmpty()) {
            for (var rule : rules) {
                if (rule.matches(request.getPath().toString(), request.getMethod().name())) {
                    if (rule.getType().equals(AuthRule.RuleType.ANONYMOUS)
                            || (rule.getType().equals(AuthRule.RuleType.AUTHENTICATED) && !user.isAnonymous())
                            || (rule.getType().equals(AuthRule.RuleType.HAS_ROLE) && matchesRole(user.getRoles(), rule.getRoles()))) {
                        break;
                    } else {
                        return returnWith(401, "Current action is not authorized!", response);
                    }
                }
            }
        }

        return webFilterChain.filter(serverWebExchange);
    }

    public static final Mono<Void> returnWith(final int status, final String message, final ServerHttpResponse response) {
        response.setRawStatusCode(status);
        if (StringUtils.isBlank(message)) {
            return response.setComplete();
        }

        var msg = response.bufferFactory().wrap(message.getBytes());
        return response.writeWith(Mono.just(msg));
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
