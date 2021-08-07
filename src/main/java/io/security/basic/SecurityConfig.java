package io.security.basic;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;

@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    UserDetailsService userDetailsService;
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .authorizeRequests()
                .anyRequest().authenticated();

        http
                // Spring Security의 Form Login 기능을 사용한다.
                .formLogin()
                // 로그인 페이지를 사용자가 지정해준다. (지정을 안하면 default로 Spring에서 제공하는 페이지로 이동한다.)
                .loginPage("/loginPage")
                // 로그인이 성공하면 이동할 페이지를 지정한다.
                .defaultSuccessUrl("/")
                // 로그인이 실패하면 이동할 페이지를 지정한다.
                .failureForwardUrl("/loginPage")
                // front에서 사용할 로그인 아이디 변수명을 설정한다.
                .usernameParameter("userId")
                // front에서 사용할 로그인 패스워드 변수명을 설정한다.
                .passwordParameter("userPw")
                // front에서 사용하는 action 변수명을 설정한다.
                .loginProcessingUrl("/login_proc")
                .successHandler(new AuthenticationSuccessHandler() {
                    @Override
                    public void onAuthenticationSuccess(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse, Authentication authentication) throws IOException, ServletException {
                        System.out.println("authentication : "+ authentication.getName());
                        httpServletResponse.sendRedirect("/");
                    }
                })
                .failureHandler(new AuthenticationFailureHandler() {
                    @Override
                    public void onAuthenticationFailure(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse, AuthenticationException e) throws IOException, ServletException {
                        System.out.println("error: "+ e.getMessage());
                        httpServletResponse.sendRedirect("/loginPage");
                    }
                })

                // authorize 가 .anyRequest().authenticated() 이므로
                // 모든 페이지는 인증이 있어야 접근이 가능하다, 하지만 로그인페이지는 인증없이 접근해야함으로
                .permitAll();

        http
                .logout()
                .logoutUrl("/logout")
                .logoutSuccessUrl("/loginPage")
                // 로그인정보가 담긴 session을 무효화시킨다.
                .addLogoutHandler(new LogoutHandler(){
                    @Override
                    public void logout(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse, Authentication authentication) {
                        HttpSession session = httpServletRequest.getSession();
                        session.invalidate();
                    }
                })
                .logoutSuccessHandler(new LogoutSuccessHandler() {
                    @Override
                    public void onLogoutSuccess(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse, Authentication authentication) throws IOException, ServletException {
                        httpServletResponse.sendRedirect("/loginPage");
                    }
                })
                // 쿠키를 삭제한다.
                .deleteCookies("remmember-me")
                ;

        // remember me 기능 사용
        // 사용자의 로그인 쿠키가 만료가 되어도, remember me 쿠키를 가지고 있다면
        // 서버에서 remember me 쿠키의 유효성을 판단하고,
        // 유효하다면 접속요청을 한 세션 정보를 조회해서 SecurityContext를 통해 Authentication 객체를 가져와서 처리함
        http
                .rememberMe()
                // Front 에서 사용할 변수
                .rememberMeParameter("remember")
                .tokenValiditySeconds(3600)
                // 사용자가 Remember me 기능을 체크하지 않아도, 서버가 자체적으로 remember me 기능을 실행하는 함수
                // 가급적이면 false로 설정하는것이 옳다
                .alwaysRemember(false)
                .userDetailsService(userDetailsService)
                ;
    }
}
