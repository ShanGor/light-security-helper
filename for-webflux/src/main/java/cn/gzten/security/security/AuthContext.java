package cn.gzten.security.security;

import io.micrometer.common.util.StringUtils;
import org.springframework.http.server.reactive.ServerHttpRequest;

public class AuthContext {
    public static final String AUTH_HEADER_ID = "Auth-Security-Id";
    public static AuthUser getAuthUser(ServerHttpRequest request) {
        var requestId = request.getHeaders().getFirst(AUTH_HEADER_ID);
        if (StringUtils.isBlank(requestId)) {
            return null;
        }
        return AbstractSecurityFilter.authUserMap.get(requestId);
    }
}
