package io.github.shangor.security;

import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;

import java.security.PublicKey;
import java.util.*;

@Slf4j
public abstract class AbstractSecurityFilterForJwt extends AbstractSecurityFilter {

    /**
     * You might need to check `kid` in the content (optionally). So now provide the content to get the key.
     * @param content
     * @return
     */
    protected abstract PublicKey getJwtKeyForVerification(Map<String, Object> content);

    protected Optional<AuthUser> getAuthUser(HttpServletRequest request) {
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
