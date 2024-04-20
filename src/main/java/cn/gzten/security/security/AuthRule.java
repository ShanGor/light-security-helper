package cn.gzten.security.security;

import org.springframework.http.HttpMethod;

import java.util.List;

public interface AuthRule {
    enum RuleType {
        ANONYMOUS,
        AUTHENTICATED,
        HAS_ROLE
    }
    HttpMethod ALL_METHODS = HttpMethod.valueOf("ALL");

    boolean matches(String path, String method);

    RuleType getType();

    List<String> getRoles();
}
