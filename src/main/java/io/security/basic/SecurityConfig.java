package io.security.basic;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.security.web.savedrequest.SavedRequest;

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

    @Autowired
    PasswordEncoder passwordEncoder;

    // Spring Security 에서 자체적으로 계정과 권한을 생성
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception{

        // 계정의 비밀번호를 암호화 시켜준다.
        String password = passwordEncoder.encode("1234");

        auth.inMemoryAuthentication().withUser("user").password(password).roles("USER");
        auth.inMemoryAuthentication().withUser("admin").password(password).roles("ADMIN");
        auth.inMemoryAuthentication().withUser("sys").password(password).roles("SYS");
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {

        // 인가 정책
        // 어떤 요청에도 인증을 받아야 자원에 접근이 가능하다
        http
                .authorizeRequests()
                .antMatchers("/user").hasRole("USER")
                .antMatchers("/admin/pay").hasAuthority("ROLE_ADMIN")
                .antMatchers("/admin/**").hasAnyRole("ADMIN","SYS")
                .antMatchers("/sys/**").access("hasRole('ADMIN') or hasRole('SYS')")
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

                // 사용자가 로그인에 실패했다가 재 성공했을때도 이전에 요청을 그대로 유지하면서 페이지로 이동하게 만든다.
                .successHandler(new AuthenticationSuccessHandler() {
                    @Override
                    public void onAuthenticationSuccess(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse, Authentication authentication) throws IOException, ServletException {
                        RequestCache requestCache = new HttpSessionRequestCache();
                        SavedRequest savedRequest = requestCache.getRequest(httpServletRequest,httpServletResponse);
                        String redirectUrl = savedRequest.getRedirectUrl();
                        httpServletResponse.sendRedirect(redirectUrl);
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

        http
                .sessionManagement()
                // 동시 세션 제어
                // 최대 동시 접근 세션 수를 1로 설정
                .maximumSessions(1)
                // 최대 세션수를 초과하였을때 서버에서의 처리
                // false : (defalut) 이전 세션을 만료시킨다
                // true : 새로운 세션의 접근을 막는다
                .maxSessionsPreventsLogin(false)
                // 세션이 만료된 경우 이동할 주소 지정
                .expiredUrl("/")
                .and()

                // 세션 고정 보호 설정
                // defalut 로 changeSessionId() 가 설정되어있다.
                // -> 새로운 인증마다 session id를 변경해준다.
                .sessionFixation().changeSessionId()
                .and()

                // 세션 정책 설정
                // defalut로는 .If_required 로 설정되어있다.
                // -> 필요시에 세션을 새로 생성한다.
                .sessionManagement()
                // SessionCreationPolicy.STATELESS
                // : 세션을 생성하지도, 사용하지도 않음 -> JWT 기반 인증 방식을 사용할때 적용한다.
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                ;

        /**
         *  인증, 인가 예외처리
         */
        http
                .exceptionHandling()

                // 인증 예외가 났을때, login 페이지로 이동하게 만든다.
                .authenticationEntryPoint(new AuthenticationEntryPoint() {
                    @Override
                    public void commence(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse, AuthenticationException e) throws IOException, ServletException {
                        httpServletResponse.sendRedirect("/login");
                    }
                })

                // 인가 예외가 났을때, denied 페이지로 이동하게 만든다.
                .accessDeniedHandler(new AccessDeniedHandler() {
                    @Override
                    public void handle(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse, AccessDeniedException e) throws IOException, ServletException {
                        httpServletResponse.sendRedirect("/denied");
                    }
                });
        http
                .csrf();
    }
}
