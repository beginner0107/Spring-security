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

## 인증 API - Form Login 인증
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
            .formLogin()
            .loginPage("/loginPage")
            .defaultSuccessUrl("/")
            .failureUrl("/login")
            .usernameParameter("userId")
            .passwordParameter("passwd")
            .loginProcessingUrl("/login_proc")
            .successHandler((request, response, authentication) -> {
              System.out.println("authentication : " + authentication.getName());
              response.sendRedirect("/");
            })
            .failureHandler(((request, response, exception) -> {
              System.out.println("exception " + exception.getMessage());
              response.sendRedirect("/login");
            }))
            .permitAll();
  }
}
```
- ```loginPage``` 
  - 사용자 정의 로그인 페이지
- ```defaultSuccessUrl```
  - 로그인 성공 후 이동 페이지
- ```failureUrl```
  - 로그인 실패 후 이동 페이지
- ```usernameParameter```
  - 아이디 파라미터명 설정
- ```passwordParameter```
  - 패스워드 파라미터명 설정
- ```loginProcessingUrl```
  - 로그인 Form Action Url
- ```successHandler```
  - 로그인 성공 후 핸들러
- ```failureHandler```
  - 로그인 실패 후 핸들러

### 아이디 파라미터명 설정, 패스워드 파라미터명 설정 의미
- 스프링 시큐리티가 만들어준 로그인 페이지에서 [아이디, 패스워드]의 기본 설정을 따르지 않고
```html
<div class="container">
      <form class="form-signin" method="post" action="/login_proc">
        <h2 class="form-signin-heading">Please sign in</h2>
        <p>
          <label for="username" class="sr-only">Username</label>
          <input type="text" id="username" name="여기가 바뀜" class="form-control" placeholder="Username" required="" autofocus="">
        </p>
        <p>
          <label for="password" class="sr-only">Password</label>
          <input type="password" id="password" name="여기가 바뀜" class="form-control" placeholder="Password" required="">
        </p>
<input name="_csrf" type="hidden" value="fe30218b-e487-4293-a845-ddd7a975da03">
        <button class="btn btn-lg btn-primary btn-block" type="submit">Sign in</button>
      </form>
</div>
```
- 이런 식으로 사용할 수 있음