package cn.gzten.security.security;

import com.fasterxml.jackson.core.type.TypeReference;
import io.jsonwebtoken.JwtException;
import io.micrometer.common.util.StringUtils;
import lombok.Builder;
import lombok.Data;

import java.util.Base64;
import java.util.Collection;
import java.util.HashMap;
import java.util.Map;

@Data
@Builder
public class JwtResult {
    private String token;
    private Map<String, Object> content;
    private AuthUser user;
    private String signature;

    private static TypeReference<Map<String, Object>> jwtContentTypeRef = new TypeReference<>() {};

    public static JwtResult parseJwt(String tokenGiven, String jwtUsernameKey, String jwtRolesKey) {
        if (StringUtils.isBlank(tokenGiven)) throw new JwtException("No JWT token provided");
        String token;
        if (tokenGiven.startsWith("Bearer ")) {
            token = tokenGiven.substring(7);
        } else {
            token = tokenGiven;
        }

        var tokens = token.split("\\.");
        if (tokens.length != 3) {
            throw new JwtException("Invalid JWT token");
        }

        var headerStr = tokens[0];
        var payloadStr = tokens[1];
        var signature = tokens[2];

        try {
            var header = JsonUtil.fromJson(Base64.getDecoder().decode(headerStr), jwtContentTypeRef);
            var payload = JsonUtil.fromJson(Base64.getDecoder().decode(payloadStr), jwtContentTypeRef);
            var content = new HashMap<>(header);
            content.putAll(payload);

            AuthUser user = new AuthUser();
            var username = content.get(jwtUsernameKey);
            if (username != null) user.setUsername(username.toString());
            var roles = content.get(jwtRolesKey);
            if (roles != null) {
                if (roles instanceof String) {
                    user.addRole(roles.toString());
                } else if (roles instanceof Integer){
                    user.addRole(roles.toString());
                } else if (roles instanceof Collection){
                    for (var role : (Collection<?>) roles) {
                        user.addRole(role.toString());
                    }
                } else if (roles.getClass().isArray()){
                    for (var role : (Object[]) roles) {
                        user.addRole(role.toString());
                    }
                }
            }

            var jwtResult = JwtResult.builder()
                    .token(token)
                    .user(user)
                    .content(content)
                    .signature(signature)
                    .build();
            return jwtResult;
        } catch (Exception e) {
            throw new JwtException("Invalid JWT token `%s`".formatted(e.getMessage()));
        }
    }
}
