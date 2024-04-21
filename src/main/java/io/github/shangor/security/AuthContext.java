package io.github.shangor.security;

import io.micrometer.common.util.StringUtils;
import org.springframework.http.server.reactive.ServerHttpRequest;

public class AuthContext {
    public static AuthUser getAuthUser(ServerHttpRequest request) {
        var requestId = request.getId();
        if (StringUtils.isBlank(requestId)) {
            return null;
        }
        var res = AbstractReactiveSecurityFilter.authUserMap.get(requestId);
        return res;
    }
}
