# Lightweight Security Helper for Spring Boot Projects

As you may know, the Spring-Security is a very good and powerful library for securing your Spring Boot projects. Even though it is very complicated to use and configure. As it is strong enough, it worth to learn and use it.
However, every time it upgrades, the API and usage changes. It would be hard for you to upgrade Spring-boot if you use the Spring-Security.

So I created this library to help you to do simple and fast security configuration easily. without Spring Security.

## Usage
- Add the dependency to your pom.xml
- Implement your `SecurityFilter` to extend the `AbstractSecurityFilter`
- Inject `AuthUser` with `@RequestAttribute(AuthUser.AUTH_USER) AuthUser user`
   ```
    @GetMapping("/test")
    public AuthUser test(@RequestAttribute(AuthUser.AUTH_USER) AuthUser user) {
        return user;
    }
   ```