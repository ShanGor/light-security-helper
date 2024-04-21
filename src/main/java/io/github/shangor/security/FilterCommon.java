package io.github.shangor.security;


import java.util.List;

public abstract class FilterCommon {
    protected String headerNameForToken() {
        return "Authorization";
    }

    protected String jwtUsernameKey() {
        return "username";
    }

    protected String jwtRolesKey() {
        return "roles";
    }

    protected abstract List<AuthRule> getAuthorizationRules();
}
