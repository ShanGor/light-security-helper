package cn.gzten.security.security;

import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.LinkedList;
import java.util.List;


@Data
@NoArgsConstructor
public class AuthUser {
    public static final String AUTH_USER = "auth_user";

    private String username;
    private List<String> roles = EMPTY_LIST;

    public AuthUser(boolean anonymous) {
        this.anonymous = anonymous;
        if (anonymous) {
            username = "Anonymous";
        }
    }

    public AuthUser addRole(String role) {
        roles.add(role);
        return this;
    }

    private boolean anonymous = false;
    public static final AuthUser ANONYMOUS_USER = new AuthUser(true);
    private static final List<String> EMPTY_LIST = new LinkedList<>();
}
