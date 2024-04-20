package cn.gzten.security.security;

import lombok.Data;
import org.springframework.http.HttpMethod;

import java.util.List;
import java.util.regex.Pattern;

@Data
public class AuthRuleRegExp implements AuthRule {
    private Pattern pathPattern;
    private String method;
    private AuthRule.RuleType type;
    List<String> roles;

    public AuthRuleRegExp(Pattern pathPattern, HttpMethod method, AuthRule.RuleType type, List<String> roles) {
        this.pathPattern = pathPattern;
        this.method = method.name();
        this.type = type;
        this.roles = roles;
    }

    @Override
    public boolean matches(String path, String method) {
        if (ALL_METHODS.name().equals(this.method) || this.method.equals(method)) {
            return pathPattern.matcher(path).matches();
        }

        return false;
    }
}
