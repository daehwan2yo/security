package io.security.basic.ajax;

import io.security.basic.Authenticate.AccountContext;
import io.security.basic.Authenticate.otherAuthenticate.FormWebAuthenticationDetails;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.transaction.annotation.Transactional;

public class AjaxAuthenticationProvider implements AuthenticationProvider {
    // DB로 부터 사용자의 정보를 받아오기 위해 Bean 주입
    @Autowired
    private UserDetailsService userDetailsService;

    // 비밀번호의 암호화 인증을 위해 Bean주입
    @Autowired
    private PasswordEncoder passwordEncoder;

    // 입력받는 Authentication 의 타입과 provider에서 로그인시 사용하는 Token의 타입이 일치하는지 확인
    @Override
    public boolean supports(Class<?> authentication) {
        return AjaxAuthenticationToken.class.isAssignableFrom(authentication);
    }

    // 실제로 검증을 위한 구현
    @Override
    @Transactional
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        String username = authentication.getName();
        String password = (String)authentication.getCredentials();

        AccountContext accountContext = (AccountContext)userDetailsService.loadUserByUsername(username);

        if(!passwordEncoder.matches(password,accountContext.getAccount().getPassword()))
            throw new BadCredentialsException("Bad Password");

        // 해당 라인까지 왔다면 모든 인증절차를 거쳤다는 의미이다.
        AjaxAuthenticationToken authenticationToken
                = new AjaxAuthenticationToken(accountContext.getAccount(),
                null,
                accountContext.getAuthorities());

        return authenticationToken;
    }
}
