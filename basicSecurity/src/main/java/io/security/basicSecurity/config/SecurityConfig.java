package io.security.basicSecurity.config;

import javax.servlet.http.HttpSession;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.UserDetailsService;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    private final UserDetailsService userDetailsService;

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
            .authorizeRequests()
            .anyRequest().authenticated()
            .and()
            .formLogin()
//            .loginPage("/loginPage")
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

        http.rememberMe()
            .rememberMeParameter("remember") // 기본 파라미터명은 remember-me
            .tokenValiditySeconds(3600) // Default 는 14일
            .alwaysRemember(true) // 리멤버 미 기능이 활성화되지 않아도 항상 실행 -> 기본 false
            .userDetailsService(userDetailsService); // 시스템에 있는 사용자 계정을 조회하는 처리과정에 필요한 클래스 등록

        http.sessionManagement()
//            .invalidSessionUrl("/invalid")
            .sessionFixation().changeSessionId()
            .maximumSessions(1)
            .maxSessionsPreventsLogin(false);
//            .expiredUrl("/expired");
    }
}