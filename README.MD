# Lightweight Security Helper for Spring Boot Projects

As you may know, the Spring-Security is a very good and powerful library for securing your Spring Boot projects. Even though it is very complicated to use and configure. As it is strong enough, it worth to learn and use it.

However, every time it upgrades, the API and usage changes. It would be hard for you to upgrade Spring-boot if you use the Spring-Security.

So I created this library to help you to do simple and fast security configuration easily, without Spring Security.

## Usage For Spring MVC
- Add the dependency to your pom.xml
- Implement your `SecurityFilter` to extend the `AbstractSecurityFilter`. (Further more do `AbstractSecurityFilterForJwt`)
  ``` Java
  @Slf4j
  @Configuration
  @Order(1)
  public class DefaultSecurityFilter extends AbstractSecurityFilter {
      public List<AuthRule> getAuthorizationRules() {
          return List.of(new AuthRuleExactMatch("/test", AuthRule.ALL_METHODS, AuthRule.RuleType.ANONYMOUS, null));
      }
  
      public Optional<AuthUser> getAuthUser(HttpServletRequest request) {
          var user = new AuthUser();
          user.setUsername("samuel");
          user.addRole("admin");
          return Optional.of(user);
      }
  }
  ```
- Inject `AuthUser` with `@RequestAttribute(AuthUser.AUTH_USER) AuthUser user`
   ``` Java
    @GetMapping("/test")
    public AuthUser test(@RequestAttribute(AuthUser.AUTH_USER) AuthUser user) {
        return user;
    }
   ```
## Usage For Webflux
- Add the dependency to your pom.xml
- Implement your `SecurityFilter` to extend the `AbstractReactiveSecurityFilter`  (Further more do `AbstractReactiveSecurityFilterForJwt`)
  ``` Java
  @Component
  @Order(1)
  public class SecurityFilter extends AbstractReactiveSecurityFilter {
    @Override
    public List<AuthRule> getAuthorizationRules() {
      return List.of(new AuthRuleExactMatch("/test-security", AuthRule.ALL_METHODS, AuthRule.RuleType.AUTHENTICATED, null));
    }
    
    @Override
    public Optional<AuthUser> getAuthUser(ServerHttpRequest request) {
      var token = tryToGetHeader("Authorization", request);
      return Optional.empty();
    }
  }
  ```
- Inject `AuthUser` with `ServerHttpRequest` then retrieve user by `AuthContext.getAuthUser(request)`
  ```
   @GetMapping("/test-security")
   public AuthUser test(ServerHttpRequest request) {
       var result = AuthContext.getAuthUser(request);
       log.info("test-security: {}", result);
       return result;
   }
  ```
## Tips
### Default Values
To override the default header name and jwt keys, you can override the following methods in your `SecurityFilter`.
``` Java
// Default values are:
protected String headerNameForToken() {
    return "Authorization";
}

protected String jwtUsernameKey() {
    return "username";
}

protected String jwtRolesKey() {
    return "roles";
}
```

# Some Utility
``` Bash
git config --global http.proxy socks5://127.0.0.1:10001
git config --global https.proxy socks5://127.0.0.1:10001
git config --global --unset http.proxy
git config --global --unset https.proxy
```
Deploy to Maven tips: https://central.sonatype.org/publish/requirements/gpg/ (After posted the keys to keyserver.ubuntu.com, need to wait a bit as sonatype got caches.)  
`clean deploy -Psigning`