package cn.gzten.security.security;

import io.micrometer.common.util.StringUtils;
import lombok.AllArgsConstructor;
import lombok.Data;
import org.springframework.http.HttpMethod;

import java.util.List;

@Data
@AllArgsConstructor
public class AuthRulePrefixMatch implements AuthRule {
    private String pathPrefix;
    private String method;
    private RuleType type;
    private List<String> roles;

    public AuthRulePrefixMatch(String pathPrefix, HttpMethod method, AuthRule.RuleType type, List<String> roles) {
        if (StringUtils.isBlank(pathPrefix)) {
            throw new IllegalArgumentException("Path cannot be null or empty");
        }
        this.pathPrefix = pathPrefix;
        this.method = method.name();
        this.type = type;
        this.roles = roles;
    }

    @Override
    public boolean matches(String path, String method) {
        if (StringUtils.isBlank(path)) return false;

        return  (path.startsWith(this.pathPrefix) && (ALL_METHODS.name().equals(this.method) || this.method.equals(method)));
    }
}
