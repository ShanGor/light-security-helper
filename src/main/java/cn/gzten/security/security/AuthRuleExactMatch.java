package cn.gzten.security.security;

import io.micrometer.common.util.StringUtils;
import lombok.Data;
import org.springframework.http.HttpMethod;

import java.util.List;

@Data
public class AuthRuleExactMatch implements AuthRule {
    private String path;
    private String method;
    private AuthRule.RuleType type;
    private List<String> roles;

    public AuthRuleExactMatch(String path, HttpMethod method, AuthRule.RuleType type, List<String> roles) {
        if (StringUtils.isBlank(path)) {
            throw new IllegalArgumentException("Path cannot be null or empty");
        }
        this.path = path;
        this.method = method.name();
        this.type = type;
        this.roles = roles;
    }

    @Override
    public boolean matches(String path, String method) {
        if (this.path.equals(path)) {
            return ALL_METHODS.name().equals(this.method) || this.method.equals(method);
        }
        return false;
    }
}
