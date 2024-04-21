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
            .failureUrl("/login.html?error=true")
            .usernameParameter("userId")
            .passwordParameter("passwd")
            .loginProcessingUrl("/login")
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

### 도식화
![img.png](image/FormLoginImage.png)

- ```UsernamePasswordAuthenticationFitler```
  - 인증처리에 관련된 필터
  - 여러 클래스들을 활용해서 인증처리를 수행

- ```AntPathRequestMatcher```
  - 일치하는 요청(url)이 왔는지 확인
  - 기본 설정은 '/login'으로 되어 있음
  - 매칭 되지 않으면 그 다음 필터로 이동 (chain.doFilter)
  - http.loginProcessingUrl("/login") -> "/login" 바꾸면 변경 가능

- ```Authentication```
  - 사용자가 입력한 username + password 값을 인증 객체에 저장
  - 인증 객체를 생성한다는 의미

- ```AuthenticationManager```
  - 인증 관리자
  - 인증 객체를 넘겨 받고, 인증 처리를 수행
  - 내부적으로 ```AuthenticationProvier```클래스 타입의 객체를 가지고 있음
    - ```AuthenticationManager``` 는 인증 처리를 위임해서 수행
    - 인증에 실패하면 ```AuthenticationException``` 인증 실패 -> 다시 ```UsernamePasswordAuthenticationFilter```가 받아서 예외에 대한 후속 작업 처리
    - 인증에 성공하면 Authentication 객체를 만들어 그 안에 인증에 성공한 User객체 또는 권한정보(Authorization)를 넣어줌
  - ```AuthenticationManager```에게 Return
    - ```AuthenticationManager```는 ```AuthenticationProvider```에게 받은 최종적인 인증 객체를 다시 Filter(```Authentication```)에게 Return

- ```Authentication```
  - 최종적으로 성공한 User객체 + 권한정보(Authorities)

- ```SecurityContext```
  - 여기에 인증 + 인가 정보를 저장
  - Session에도 저장

- ```SuccessHandler```
  - 성공하면 이 핸들러(작업)을 수행

### 실습
#### debug point
- ```UsernamePasswordAuthenticationFilter```
  - ```AbstractAuthenticationProcessingFilter``` 부모 필터의 doFilter 수행
```java
public abstract class AbstractAuthenticationProcessingFilter extends GenericFilterBean implements ApplicationEventPublisherAware, MessageSourceAware {
	private void doFilter(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
			throws IOException, ServletException {
		if (!requiresAuthentication(request, response)) { // 설정한 "/login"과 일치하는지 확인
			chain.doFilter(request, response); // 일치하지 않으면 다음 필터로
			return;
		}
		try {
            // 인증을 수행
			Authentication authenticationResult = attemptAuthentication(request, response);
			if (authenticationResult == null) {
				// return immediately as subclass has indicated that it hasn't completed
				return;
			}
			this.sessionStrategy.onAuthentication(authenticationResult, request, response);
			// Authentication success
			if (this.continueChainBeforeSuccessfulAuthentication) {
				chain.doFilter(request, response);
			}
			successfulAuthentication(request, response, chain, authenticationResult);
		}
		catch (InternalAuthenticationServiceException failed) {
			this.logger.error("An internal error occurred while trying to authenticate the user.", failed);
			unsuccessfulAuthentication(request, response, failed);
		}
		catch (AuthenticationException ex) {
			// Authentication failed
			unsuccessfulAuthentication(request, response, ex);
		}
	}
}
```
  - ```attemptAuthentication```는 ```UsernamePasswordAuthenticationFilter```의 메서드로 수행
```java
public class UsernamePasswordAuthenticationFilter extends AbstractAuthenticationProcessingFilter {

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request,
        HttpServletResponse response)
        throws AuthenticationException {
        if (this.postOnly && !request.getMethod().equals("POST")) { // POST로 왔는지 확인
            throw new AuthenticationServiceException(
                "Authentication method not supported: " + request.getMethod());
        }
        String username = obtainUsername(request); 
        username = (username != null) ? username : "";
        username = username.trim();
        String password = obtainPassword(request);
        password = (password != null) ? password : "";
        UsernamePasswordAuthenticationToken authRequest = new UsernamePasswordAuthenticationToken(
            username, password); // Authentication객체에 username, password를 담아
        // Allow subclasses to set the "details" property
        setDetails(request, authRequest);
        return this.getAuthenticationManager().authenticate(authRequest); // 인증 객체를 AuthenticationManager에 넘김
    }
}
```
```java
public class ProviderManager implements AuthenticationManager, MessageSourceAware, InitializingBean {

    @Override
    public Authentication authenticate(Authentication authentication)
        throws AuthenticationException {
        Class<? extends Authentication> toTest = authentication.getClass();
        AuthenticationException lastException = null;
        AuthenticationException parentException = null;
        Authentication result = null;
        Authentication parentResult = null;
        int currentPosition = 0;
        int size = this.providers.size();
        for (AuthenticationProvider provider : getProviders()) {
            if (!provider.supports(toTest)) {
                continue;
            }
            if (logger.isTraceEnabled()) {
                logger.trace(LogMessage.format("Authenticating request with %s (%d/%d)",
                    provider.getClass().getSimpleName(), ++currentPosition, size));
            }
            try {
                result = provider.authenticate(authentication); // 인증 작업 수행 Provider에게 위임
                if (result != null) {
                    copyDetails(authentication, result);
                    break;
                }
            } catch (AccountStatusException | InternalAuthenticationServiceException ex) {
                prepareException(ex, authentication);
                throw ex;
            } catch (AuthenticationException ex) {
                lastException = ex;
            }
        }
        /* 생략 */
    }
}
```
  - ```AuthenticationProvider```를 상속한 ```AbstractUserDetailsAuthenticationProvider```에서 authenticate진행
```java
public abstract class AbstractUserDetailsAuthenticationProvider
        implements AuthenticationProvider, InitializingBean, MessageSourceAware {

    @Override
    public Authentication authenticate(Authentication authentication)
        throws AuthenticationException {
        Assert.isInstanceOf(UsernamePasswordAuthenticationToken.class, authentication,
            () -> this.messages.getMessage("AbstractUserDetailsAuthenticationProvider.onlySupports",
                "Only UsernamePasswordAuthenticationToken is supported"));
        String username = determineUsername(authentication);
        boolean cacheWasUsed = true;
        UserDetails user = this.userCache.getUserFromCache(username);
        if (user == null) {
            cacheWasUsed = false;
            try {
                user = retrieveUser(username, (UsernamePasswordAuthenticationToken) authentication);
            } catch (UsernameNotFoundException ex) {
                this.logger.debug("Failed to find user '" + username + "'");
                if (!this.hideUserNotFoundExceptions) {
                    throw ex;
                }
                throw new BadCredentialsException(this.messages
                    .getMessage("AbstractUserDetailsAuthenticationProvider.badCredentials",
                        "Bad credentials"));
            }
            Assert.notNull(user,
                "retrieveUser returned null - a violation of the interface contract");
        }
        try {
            this.preAuthenticationChecks.check(user);
            additionalAuthenticationChecks(user,
                (UsernamePasswordAuthenticationToken) authentication);
        } catch (AuthenticationException ex) {
            if (!cacheWasUsed) {
                throw ex;
            }
            // There was a problem, so try again after checking
            // we're using latest data (i.e. not from the cache)
            cacheWasUsed = false;
            user = retrieveUser(username, (UsernamePasswordAuthenticationToken) authentication);
            this.preAuthenticationChecks.check(user);
            additionalAuthenticationChecks(user,
                (UsernamePasswordAuthenticationToken) authentication);
        }
        this.postAuthenticationChecks.check(user);
        if (!cacheWasUsed) {
            this.userCache.putUserInCache(user);
        }
        Object principalToReturn = user;
        if (this.forcePrincipalAsString) {
            principalToReturn = user.getUsername();
        }
        return createSuccessAuthentication(principalToReturn, authentication, user);
    }
}
```
  - ```DaoAuthenticationProvider```의 ```createSuccessAuthentication```호출
  - ```AbstractUserDetailsAuthenticationProvider```을 상속받은 ```DaoAuthenticationProvider```
```java
public abstract class AbstractUserDetailsAuthenticationProvider
        implements AuthenticationProvider, InitializingBean, MessageSourceAware {
  protected Authentication createSuccessAuthentication(Object principal, Authentication authentication,
          UserDetails user) {
    UsernamePasswordAuthenticationToken result = new UsernamePasswordAuthenticationToken(principal,
            authentication.getCredentials(), this.authoritiesMapper.mapAuthorities(user.getAuthorities()));
    result.setDetails(authentication.getDetails());
    this.logger.debug("Authenticated user");
    return result;
  }
}
```

  - 다시 ```AbstractAuthenticationProcessingFilter```로 와서
```java
    Authentication authenticationResult = attemptAuthentication(request, response);
```
  - 를 반환받고(인증, 인가정보가 담긴 객체)
  - ```successfulAuthentication```을 호출

```java
public abstract class AbstractAuthenticationProcessingFilter extends GenericFilterBean
        implements ApplicationEventPublisherAware, MessageSourceAware {

    protected void successfulAuthentication(HttpServletRequest request,
        HttpServletResponse response, FilterChain chain,
        Authentication authResult) throws IOException, ServletException {
        SecurityContext context = SecurityContextHolder.createEmptyContext();
        context.setAuthentication(authResult);
        SecurityContextHolder.setContext(context);
        if (this.logger.isDebugEnabled()) {
            this.logger.debug(LogMessage.format("Set SecurityContextHolder to %s", authResult));
        }
        this.rememberMeServices.loginSuccess(request, response, authResult);
        if (this.eventPublisher != null) {
            this.eventPublisher.publishEvent(
                new InteractiveAuthenticationSuccessEvent(authResult, this.getClass()));
        }
        this.successHandler.onAuthenticationSuccess(request, response, authResult);
    }
}
```
  - ```onAuthenticationSuccess```를 호출
```java
public interface AuthenticationSuccessHandler {

    default void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
        FilterChain chain,
        Authentication authentication) throws IOException, ServletException {
        onAuthenticationSuccess(request, response, authentication);
        chain.doFilter(request, response);
    }
}
```

### FilterChainProxy
- FilterChainProxy의 등록된 각각의 필터들

![img.png](image/FilterChainProxy.png)

```java
public class FilterChainProxy extends GenericFilterBean {
  private static final class VirtualFilterChain implements FilterChain {
    @Override
    public void doFilter(ServletRequest request, ServletResponse response) throws IOException, ServletException {
      /* 생략 */  
      Filter nextFilter = this.additionalFilters.get(this.currentPosition - 1);
      nextFilter.doFilter(request, response, this); // 디버깅 포인트
    }
  }
}
```

## 인증 API - Logout

```java
        http.logout()
            .logoutUrl("/logout")
            .logoutSuccessUrl("/login")
            .deleteCookies("JSESSIONID", "remember-me")
            .addLogoutHandler((request, response, authentication) -> {
                HttpSession session = request.getSession();
                session.invalidate();
            })
            .logoutSuccessHandler(
                (request, response, authentication) -> response.sendRedirect("/login"));
```
- ```http.logout()```
  - 로그아웃 기능이 작동함
- ```logoutUrl ```
  - 로그아웃 처리 URL
- ```logoutSuccessUrl```
  - 로그아웃 성공 후 이동페이지
- ```deleteCookies("JSESSIONID", "remember-me")```
  - 로그아웃 후 쿠키 삭제
- ```addLogoutHandler(logoutHandler())```
  - 로그아웃 핸들러
  - 기본적으로 스프링 시큐리티가 로그아웃 시 제공하는 구현체가 있음
  - 세션 삭제, 인증 토큰 삭제(기본 제공)
  - 그 외로 로그아웃이 이루어 졌을 때, 추가적으로 하고 싶은 작업이 있을 경우 커스텀해서 사용
- ```logoutSuccessHandler(logoutSuccessHandler())```
  - 로그아웃 성공 후 핸들러
  - 로그아웃이 성공적으로 수행된 후 실행될 핸들러
### 도식화
![img.png](image/logoutFilter.png)

- ```LogoutFilter```
  - 요청을 받아서 기본 설정 -> POST
  - ```AntPathRequestMatcher```에게 넘김
- ```AntPathRequestMatcher```
  - "/설정한 URL"로 요청이 왔는지 확인
  - URL과 일치하지 않으면, 다음 필터로 넘어가면서 로그아웃에 실패
- ```Authentication```
  - ```SecurityContext```의 인증 객체를 가지고 와서 ```LogoutHandler```에게 넘김
- ```SecurityContextLogoutHandler```
  - ```LogoutHandler``` 구현체
  - 세션을 무효화
  - 쿠키 삭제
  - SecurityContextHolder.clearContext() -> 인증 객체(Authentication) 삭제
- ```SimpleUrlLogoutSuccessHandler```
  - 로그아웃에 성공한 ```LogoutFilter```는 ```SimpleUrlLogoutSuccessHandler```를 호출한다.
  - 로그인 페이지로 redirect

## 인증 API - Remember Me 인증
1. 세션이 만료되고 웹 브라우저가 종료된 후에도 어플리케이션이 사용자를 기억하는 기능
2. Remember-Me 쿠키에 대한 Http 요청을 확인한 후 토큰 기반 인증을 사용해 유효성을 검사하고 토큰이 검증되면 사용자는 로그인된다.
3. 사용자 라이프 사이클
   - 인증 성공(Remember-Me쿠키 설정)
   - 인증 실패(쿠키가 존재하면 쿠키 무효화)
   - 로그아웃(쿠키가 존재하면 쿠키 무효화)

```java
        http.rememberMe()
            .rememberMeParameter("remember")
            .tokenValiditySeconds(3600)
            .alwaysRemember(true) 
            .userDetailsService(userDetailsService);
```

- ```rememberMe()```
  - rememberMe 기능 활성화
- ```rememberMeParameter("remember")```
  - 기본 파라미터명은 remember-me
- ```totkenValiditySeconds(3600)```
  - default는 14일
- ```userDetailsService```
  - 시스템에 있는 사용자 계정을 조회하는 처리과정에 필요한 클래스 등록


### RememberMeAuthenticationFilter
![img.png](image/remembermeAuthenticationFilter.png)

- ```RememberMeAuthenticationFilter```
  - SecurityContext의 인증 객체가 없는 경우 작동
  - Session이 만료, 비활성화 되었을 경우 -> rememberMeToken을 가져오는 경우 작동
- ```RmemeberMeServices```
  - 두개의 구현체
    - ```TokenBasedRememberMeServices```
      - 메모리에서 토큰을 저장한 것과 사용자가 요청을 할 때 가지고 온 쿠키(토큰)과 비교해서 인증 처리
      - 기본 14일 만료 기간
    - ```PersistentTokenBasedRememberMeServices```
      - DB에 서비스에서 발급할 토큰을 저장하고
      - 그 토큰을 클라이언트에서 가지고 온 쿠키(토큰)과 비교해서 인증 처리
  - Token Cookie를 추출
  - Token이 존재할 경우
  - Decode Token -> 정상 유무를 판단
    - 정상이 아닐 경우 예외
  - 토큰의 값이 일치하는지 확인
    - 일치하지 않을 경우 예외
  - User 계정이 존재하는지 확인
    - DB에 저장된 유저를 조회해서, 존재하게 되면 다음 단계로
  - 새로운 ```Authentication``` 생성
  - ```AuthenticationManager```에게 인증객체를 넘겨주면서 인증 처리

### RememberMeAuthenticationFilter 요약
1. 이 필터는 rememberMe 기능을 체크했을 때 타게된다.
2. 세션안에 SecurityContext가 존재하는 것
3. 세션이 만료되었을 경우 rememberMeToken을 이용해서 인증을 수행
4. 어찌보면, JWT의 refreshToken과 유사한 점이 있음


## AnonymousAuthenticationFilter
![img.png](image/AnonymousAuthenticationFilter.png)

- 익명사용자 인증 처리 필터
- 익명사용자와 인증 사용자를 구분해서 처리하기 위한 용도로 사용
- 화면에서 인증 여부를 구현할 때 isAnonymous()와 isAuthenticated() 로 구분해서 사용
  - isAnonymous() = true -> 로그인 페이지 보여줌
  - isAuthentication() = true -> 로그아웃 표시
- 인증객체를 세션에 저장하지 않는다.

## 인증 API - 동시 세션 제어

1. 이전 사용자 세션 만료
   - A 유저가 Chrome에서 아이디와 비밀번호를 입력하여 로그인을 수행한다.
   - A 유저가 Edge에서 아이디와 비밀번호를 입력하여 로그인을 수행한다.
   - Chrome에서 발급된 세션은 Edge에서 로그인을 성공하면 이전 사용자 세션은 만료되게 된다.
   - Chrome에서 사용하던 계정은 만료가 되고, Edge에서는 문제 없이 사용할 수 있다.

2. 현재 사용자 인증 실패
  - A 유저가 Chrome에서 아이디와 비밀번호를 입력하여 로그인을 수행한다.
  - A 유저가 Edge에서 아이디와 비밀번호를 입력한다.
  - Edge에서 로그인을 수행함과 동시에 인증 예외가 발생한다.
  - Chrome에서 발급받은 세션을 그대로 유지하면서 서비스를 이용할 수 있다.

```java
.invalidSessionUrl("/invalid")
.maximumSessions(1)
.maxSessionsPreventsLogin(true)
.expiredUrl("/expired");
```

- ```invalidSessionUrl("/URL")```
  - 세션이 유효하지 않을 때 이동할 페이지
- ```maximumSessions(최대허용가능세션수)```
  - 최대 허용 가능 세션수
  - -1이면 무제한 로그인 세션을 허용한다.
- ```maxSessionsPreventsLogin```
  - true -> 동시 로그인을 차단 -> 2번 케이스
  - false -> 기존 세션을 만료시키는 방법 -> 1번 케이스(default)
- ```expiredUrl("/URL")```
  - 세션이 만료된 경우 이동 할 페이지
  - ```invalidSessionUrl```이 먼저 선언되어 있으면 우선순위에서 밀려 수행되지 않는다.
  - 두 메서드를 같이 쓰는 것은 ```expiredUrl```에게는 의미가 없다.

## 인증 API - 세션 고정 보호
- a라는 헤커가 b라는 서버에게 c라는 session을 발급받는다.(인증 성공)
- a(해커)는 d라는 유저에게 서버에서 발급받은 session을 건네주고
- d라는 유저는 서버에서 발급받은 c라는 세션을 가지고 b라는 서버에 접속할 수 있게 된다.
- 하나의 세션으로 두 명의 유저가 존재하는 것
- 사용자가 로그인을 시도했을 때, 세션 값을 새로 발급해주지 않는다면 생길 일

```java
http.sessionManagement()
    .sessionFixation().changeSessionId()
```
- changeSessionId()는 Servlet 3.1 이상에서 기본 값
- migrateSession은 Servlet 3.1 이하에서 작동하도록 기본 값으로 설정되어 있음 -> 이전의 속성 값을 그대로 재사용
- newSession은 세션이 발급되고 재 세션도 발급되지만 이전의 세션에서 설정한 여러가지 속성의 값들을 사용하지 못하고 새롭게 속성을 설정해야 함
- none 가장 취약한 설정 - 세션공격에 취약

```java
public SessionManagementConfigurer<H> newSession() {
    SessionFixationProtectionStrategy sessionFixationProtectionStrategy = new SessionFixationProtectionStrategy();
    sessionFixationProtectionStrategy.setMigrateSessionAttributes(false);
    setSessionFixationAuthenticationStrategy(sessionFixationProtectionStrategy);
    return SessionManagementConfigurer.this;
}

public SessionManagementConfigurer<H> migrateSession() {
    setSessionFixationAuthenticationStrategy(new SessionFixationProtectionStrategy());
    return SessionManagementConfigurer.this;
}

public SessionManagementConfigurer<H> changeSessionId() {
    setSessionFixationAuthenticationStrategy(new ChangeSessionIdAuthenticationStrategy());
    return SessionManagementConfigurer.this;
}

public SessionManagementConfigurer<H> none() {
    setSessionFixationAuthenticationStrategy(new NullAuthenticatedSessionStrategy());
    return SessionManagementConfigurer.this;
}
```

## 인증 API - 세션 정책
```java
http.sessionManagement()
        .sessionCreationPolicy(SessionCreationPolicy.If_Required)
```
- ```sessionCreationPolicy()```
  - 세션 관리 기능이 작동함

1. ```SessionCreationPolicy.Always```
  - 스프링 시큐리티가 항상 세션 생성
2. ```SessionCreationPolicy.If_Required```
  - 스프링 시큐리티가 필요 시 생성(기본값) 
3. ```SessionCreationPolicy.Never```
  - 스프링 시큐리티가 생성하지 않지만 이미 존재하면 사용
4. ```SessionCreationPolicy.Stateless```
  - 스프링 시큐리티가 생성하지 않고 존재해도 사용하지 않음

### ```SessionManagementFilter```

1. 세션 관리
  - 인증 시 사용자의 세션정보를 등록, 조회, 삭제 등의 세션 이력을 고나리
2. 동시적 세션 제어
  - 동일 계정으로 접속이 허용되는 최대 세션수를 제한
3. 세션 고정 보호
  - 인증 할 때마다 세션쿠키를 새로 발급하여 공격자의 쿠키 조작을 방지
4. 세션 생성 정책
  - Always, If_Required, Never, Stateless

### ```ConcurrnetSessionFilter```
- 매 요청 마다 현재 사용자의 세션 만료 여부 체크
- 세션이 만료되었을 경우 즉시 만료 처리

## 인가 API - 권한 설정

- 선언적 방식
  - URL
    - ```http.antMatchers("/users/**").hasRole("USER")```
  - Method
    - ```@PreAuthorize("hasRole('USER')")```
    - public void user() {System.out.println("user")}

- 동적 방식 - DB 연동 프로그래밍
  - URL
  - Method


### 선언적 방식

```java
http
  .antMatcher("/shop/**")
  .authorizeRequests()
  .antMatchers("/shop/login", "/shop/users/**").permitAll()
  .antMatchers("/shop/mypage").hasRole("USER")
  .antMatchers("/shop/admin/pay").access("hasRole('ADMIN')")
  .antMatchers("/shop/admin/**").access("hasRole('ADMIN') or hasRole('SYS')")
  .anyRequest().authenticated();
```

- 주의 사항
  - 설정 시 구체적인 경로가 먼저 오고 그것 보다 큰 범위의 경로가 뒤에 오도록 해야 한다.

## 인가 API - 표현식
| 메소드                     | 동작                                 |
|-------------------------|------------------------------------|
| authenticated()         | 인증된 사용자의 접근을 허용                    |
| fullyAuthenticated()    | 인증된 사용자의 접근을 허용, rememberMe 인증 제외  |
| permitAll()             | 무조건 접근을 허용                         |
| denyAll()               | 무조건 접근을 허용하지 않음                    |
| anonymous()             | 익명사용자의 접근을 허용                      |
| rememberMe()            | 기억하기를 통해 인증된 사용자의 접근을 허용           |
| access(String)          | 주어진 SpEL 표현식의 평과 결과가 true이면 접근을 허용 |
| hasRole(String)         | 사용자가 주어진 역할이 있다면 접근을 허용            |
| hasAuthorities(String)  | 사용자가 주어진 권한이 있다면                   |
| hasAnyRole(String)      | 사용자가 주어진 권한이 있다면 접근을 허용            |
| hasAnyAuthority(String) | 사용자가 주어진 권한 중 어떤 것이라도 있다면 접근을 허용   |
| hasIpAddress(String)    | 주어진 IP로부터 요청이 왔다면 접근을 허용           |


## 인증/인가 API - ```ExceptionTranslationFilter```

- ```AuthenticationException```
  - 인증 예외 처리
    1. ```AuthenticationEntryPoint``` 호출
       - 로그인 페이지 이동, 401 오류 코드 전달 등
    2. 인증 예외가 발생하기 전의 요청 정보를 저장
      - ```RequestCache``` - 사용자의 이전 요청 정보를 세션에 저장하고 이를 꺼내 오는 캐시 메커니즘
        - ```SavedRequest``` - 사용자가 요청했던 request 파라미터 값들, 그 당시의 헤더값들 등이 저장

- ```AccessDeniedException```
  - 인가 예외 처리
    - ```AccessDeniedHandler``` 에서 예외 처리하도록 제공

![img.png](image/ExceptionTranslationFilter.png)

```java
http.exceptionHandling()
        .authenticationEntryPoint(authenticationEntryPoint())
        .accessDeniedHandler(accessDeniedHandler())
```
- ```.authenticationEntryPoint(authenticationEntryPoint())```
  - 인증 실패 시 처리
- ```.accessDeniedHandler(accessDeniedHandler())```
  - 인가 실패 시 처리


## Form 인증 - CsrfFilter
- 모든 요청에 랜덤하게 생성된 토큰을 HTTP 파라미터로 요구
- 요청 시 전달되는 토큰 값과 서버에 저장된 실제 값과 비교한 후 만약 일치하지 않으면 요청은 실패한다.

- Client
```html
<input type="hidden" name="${_csrf.parameterName}" value="${_csrf.token}" />
```
- HTTP 메소드 : PATCH, POST, PUT, DELETE

- Spring Security
```java
http.csrf();
http.csrf().disabled();
```
- ```http.csrf()```
  - 기본 활성화되어 있음
- ```http.csrf().disabled()```
  - 비활성화

### 예시
1. 사용자가 A라는 뱅킹 웹 사이트에 로그인하여 세션을 시작(인증, 인가 O)
2. 사용자가 A 웹 사이트를 닫지 않고, 새 탭에서 공격자가 만든 웹 사이트 B에 접속(방법은 이메일 등등)
3. B에는 ```<img src="http://bbbb.com/transfer?to=attacker&amount=1000">```이라는 코드가 있음
4. 사용자는 이 이미지를 클릭하는 동시에 A서버(웹사이트)에게 요청을 보냄
5. A사이트는 인증/인가가 성공한 사용자의 쿠키를 받아 요청을 처리하게 됨(사용자가 보낸 것처럼 보임)
6. attacker의 계좌로 1000달러가 이체되는 현상


## 위임 및 필터 빈 초기화
- ```DelegatingFilterProxy```
  - 서블릿 필터는 스프링에서 정의된 빈을 주입해서 사용할 수 없음
  - 특정한 이름을 가진 스프링 빈을 찾아 그 빈에게 요청을 위임
    - ```springSecurityFilterChain``` 이름으로 생성된 빈을 ```ApplicationContext``` 에서 찾아 요청을 위임
    - 실제 보안처리를 하지 않음

![img.png](image/FilterChainProxy.png)

1. ```springSecurityFilterChain``` 의 이름으로 생성되는 필터 빈
2. ```DelegatingFilterProxy``` 으로 부터 요청을 위임 받고 실제 보안 처리
3. 스프링 시큐리티 초기화 시 생성되는 필터들을 관리하고 제어
  - 스프링 시큐리티가 기본적으로 생성하는 필터
  - 설정 클래스에서 API 추가 시 생성되는 필터
4. 사용자의 요청을 필터 순서대로 호출하여 전달
5. 사용자정의 필터를 생성해서 기존의 필터 전,후로 추가 가능
  - 필터의 순서를 잘 정의
6. 마지막 필터까지 인증 및 인가 예외가 발생하지 않으면 보안 통과

![img.png](image/DelegatingFilterProxy.png)