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
    - 

### HttpSecurity
- 세부적인 보안 기능을 설정할 수 있는 API 제공
- 인증 API
- 인가 API