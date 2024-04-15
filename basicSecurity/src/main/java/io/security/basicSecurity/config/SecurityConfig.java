package io.security.basicSecurity.config;

import java.io.IOException;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import org.apache.catalina.session.StandardSession;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;

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
    }
}