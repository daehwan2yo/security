package io.security.basic.config;

import io.security.basic.Authorize.PermitAllFilter;
import io.security.basic.Authorize.SecurityResourceService;
import io.security.basic.Authorize.UrlFilterInvocationSecurityMetadataSource;
import io.security.basic.Authorize.UrlResourceMapFactoryBean;
import io.security.basic.ajax.AjaxLoginProcessingFilter;
import io.security.basic.roleHierarchy.RoleHierarchyServiceImpl;
import org.springframework.beans.factory.FactoryBean;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.security.servlet.PathRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.access.AccessDecisionManager;
import org.springframework.security.access.AccessDecisionVoter;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.access.hierarchicalroles.RoleHierarchyImpl;
import org.springframework.security.access.vote.AffirmativeBased;
import org.springframework.security.access.vote.RoleHierarchyVoter;
import org.springframework.security.access.vote.RoleVoter;
import org.springframework.security.authentication.AuthenticationDetailsSource;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.FilterInvocation;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.access.intercept.FilterInvocationSecurityMetadataSource;
import org.springframework.security.web.access.intercept.FilterSecurityInterceptor;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.security.web.savedrequest.SavedRequest;
import org.springframework.security.web.util.matcher.RequestMatcher;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;

@Configuration
@EnableWebSecurity
@Order(1)
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    private AuthenticationProvider authenticationProvider;
    @Autowired
    private AuthenticationDetailsSource authenticationDetailsSource;
    @Autowired
    private AuthenticationSuccessHandler authenticationSuccessHandler;
    @Autowired
    private AuthenticationFailureHandler authenticationFailureHandler;
    @Autowired
    private AccessDeniedHandler accessDeniedHandler;
    // 인가 처리가 필요없는 자원
    // PermitAllFilter의 생성자로 전달한다.
    private String[] permitAllResources = {"/","/login","/user/login/**"};


    @Override
    protected AuthenticationManager authenticationManager() throws Exception {
        return super.authenticationManagerBean();
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception{
        auth
            .authenticationProvider(authenticationProvider);
    }

    // web ignoring 설정
    // 정적 파일에 대해 권한을 부여하지않는다.
    @Override
    public void configure(WebSecurity web) throws Exception {
        web
                .ignoring()
                .requestMatchers(PathRequest.toStaticResources().atCommonLocations())
                ;
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {

        http
                .authorizeRequests()
                // 로그인 실패시 이동할 denied 페이지로의 권한은 없어야함
                .antMatchers("/","/users","/login*").permitAll()
                .antMatchers("/mypage").hasRole("USER")
                .antMatchers("/messages").hasRole("MANAGER")
                .antMatchers("/config").hasRole("ADMIN")
                .anyRequest().authenticated()
                .and()

                .formLogin()
                .loginPage("/login")
                .loginProcessingUrl("/login_proc")
                .defaultSuccessUrl("/")
                .authenticationDetailsSource(authenticationDetailsSource)
                .successHandler(authenticationSuccessHandler)
                .failureHandler(authenticationFailureHandler)
                .permitAll()
                ;

        http
                .sessionManagement()
                .maximumSessions(2)
                .maxSessionsPreventsLogin(false)
                ;
        http
                .exceptionHandling()
                .accessDeniedHandler(accessDeniedHandler);
        http
                .addFilterBefore(customFilterSecurityInterceptor(),FilterSecurityInterceptor.class);
    }

    // Custom 인가 Filter
    @Bean
    public PermitAllFilter customFilterSecurityInterceptor() throws Exception {

        // permitAll 을 해줄 자원을 넘겨줘야한다.
        PermitAllFilter permitAllFilter = new PermitAllFilter(permitAllResources);
        // securityMetadataSource 설정
        // -> 해당 객체로 DB로부터 자원요소와 권한 요소를 불러온다.
        permitAllFilter.setSecurityMetadataSource(urlFilterInvocationSecurityMetadataSource());
        // AuthenticationManager 설정
        permitAllFilter.setAuthenticationManager(authenticationManager());

        // 위 두 구문을 통해 3요소를 불러온후 처리를 담당할 AccessDecisionManager 설정
        permitAllFilter.setAccessDecisionManager(affirmativeBased());

        return permitAllFilter;
    }

    @Bean
    public RoleHierarchyImpl roleHierarchyImpl(){
        return new RoleHierarchyImpl();
    }


    private FilterInvocationSecurityMetadataSource urlFilterInvocationSecurityMetadataSource() throws Exception{
        // urlFilterInvocationSecurityMetadataSource 에 DB의 자원, 권한 Map 정보를 전달해준다.
        return new UrlFilterInvocationSecurityMetadataSource(urlResourceMapFactoryBean().getObject());
    }

    private FactoryBean<LinkedHashMap<RequestMatcher,List<ConfigAttribute>>> urlResourceMapFactoryBean(){
        return new UrlResourceMapFactoryBean();
    }

    private AccessDecisionManager affirmativeBased(){
        return new AffirmativeBased(getAccessDecisionVoters());
    }
    private List<AccessDecisionVoter<?>> getAccessDecisionVoters(){

        List<AccessDecisionVoter<? extends Object>> accessDecisionVoterList = new ArrayList<>();
        accessDecisionVoterList.add(roleVoter());


        return accessDecisionVoterList;
    }

    private AccessDecisionVoter<? extends Object> roleVoter() {
        RoleHierarchyVoter roleHierarchyVoter = new RoleHierarchyVoter(roleHierarchyImpl());
        return roleHierarchyVoter;
    }
}
