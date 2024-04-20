# Lightweight Security Helper for Spring Boot Projects

As you may know, the Spring-Security is a very good and powerful library for securing your Spring Boot projects. Even though it is very complicated to use and configure. As it is strong enough, it worth to learn and use it.

However, every time it upgrades, the API and usage changes. It would be hard for you to upgrade Spring-boot if you use the Spring-Security.

So I created this library to help you to do simple and fast security configuration easily, without Spring Security.

## Usage For Spring MVC
- Add the dependency to your pom.xml
- Implement your `SecurityFilter` to extend the `AbstractSecurityFilter`
  ```
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
   ```
    @GetMapping("/test")
    public AuthUser test(@RequestAttribute(AuthUser.AUTH_USER) AuthUser user) {
        return user;
    }
   ```