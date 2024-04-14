# Spring Security 
### Description
- 회사에 적용된 버전(jdk1.8)을 기준

### Environment
- Spring Boot 2.6.2
- Spring Security 5.6.1
- Gradle

## 인증 API - 사용자 정의 보안 기능 구현

![img.png](image/img.png)

### WebSecurityConfigurerAdapter
- 스프링 시큐리티의 웹 보안 기능 초기화 및 설정

### SecurityConfig
- 사용자 정의 보안 클래스

```java
@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
            .authorizeRequests()
            .anyRequest().authenticated()
            .and()
            .formLogin();
    }
}
```
- 어노테이션 설명
  - ```@Configuration```
    - Singleton 빈으로 등록하는 과정
    - 내부를 보면 ```Component```어노테이션을 확인할 수 있고, 스프링 컨테이너 빈으로 스캔 됨을 알수 있음
  - ```@EnableWebSecurity```
    - ```WebSecurityConfiguration```
    - ```SpringWebMvcImportSelector```
    - ```HttpSecurityConfiguration```
    - 위의 3개의 클래스를 **IMPORT**
    - 스프링 시큐리티를 활성화하고 웹 보안 설정을 구성하는데 사용
- 작동 원리
  - 스프링 부트가 실행되면서 스프링 시큐리티 관련 클래스를 로드하고, ```WebSecurityConfigurerAdapter```를 수행하면서, Default Security 설정을 바탕으로 보안 활성화
  - ```WebSecurityConfigurerAdapter```를 Override한다. (스프링의 원리가 녹아 있음)
  - 내가 만든 ```WebSecurityConfigurerAdapter```가 수행된다.
  - 건전지 A가 있는데, 건전지 A의 공통 기능은 그대로 수행하면서 세부 구현을 다르게 할 수 있음

### HttpSecurity
- 세부적인 보안 기능을 설정할 수 있는 API 제공
- 인증 API
- 인가 API