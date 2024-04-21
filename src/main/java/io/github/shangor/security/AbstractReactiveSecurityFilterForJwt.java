package io.github.shangor.security;

import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.server.reactive.ServerHttpRequest;

import java.security.PublicKey;
import java.util.Map;
import java.util.Optional;

@Slf4j
public abstract class AbstractReactiveSecurityFilterForJwt extends AbstractReactiveSecurityFilter {

    /**
     * You might need to check `kid` in the content (optionally). So now provide the content to get the key.
     * @param content
     * @return
     */
    protected abstract PublicKey getJwtKeyForVerification(Map<String, Object> content);

    protected Optional<AuthUser> getAuthUser(ServerHttpRequest request) {
        String token = tryToGetHeader(headerNameForToken(), request);
        try {
            var res = JwtResult.parseJwt(token, jwtUsernameKey(), jwtRolesKey());
            try {
                var key = getJwtKeyForVerification(res.getContent());
                Jwts.parser().verifyWith(key).build().parse(res.getToken());
                return Optional.of(res.getUser());
            } catch (JwtException e) {
                throw new RuntimeException(e.getMessage());
            }
        } catch (JwtException e) {
            return Optional.empty();
        }
    }
}
