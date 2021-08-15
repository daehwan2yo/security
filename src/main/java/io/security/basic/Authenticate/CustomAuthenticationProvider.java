package io.security.basic.Authenticate;

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

/**
 *  DB에서 조회한 사용자의 정보와 사용자가 입력한 정보의 매칭을 확인해
 *  실제 인증을 처리하는 객체이다.
 *  (UserDetailsService는 단순히 DB에 정보가 있는지 조회하고 가져오기만 한다면,
 *  해당 객체를 가져온 정보를 실제 입력받은 정보와 일치하는지 확인한다.)
 *
 *  AuthenticationProvider interface를 구현한다.
 */
public class CustomAuthenticationProvider implements AuthenticationProvider {

    // DB로 부터 사용자의 정보를 받아오기 위해 Bean 주입
    @Autowired
    private UserDetailsService userDetailsService;

    // 비밀번호의 암호화 인증을 위해 Bean주입
    @Autowired
    private PasswordEncoder passwordEncoder;

    // 입력받는 Authentication 의 타입과 provider에서 로그인시 사용하는 Token의 타입이 일치하는지 확인
    @Override
    public boolean supports(Class<?> authentication) {
        return UsernamePasswordAuthenticationToken.class.isAssignableFrom(authentication);
    }

    // 실제로 검증을 위한 구현
    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        String username = authentication.getName();
        String password = (String)authentication.getCredentials();

        AccountContext accountContext = (AccountContext)userDetailsService.loadUserByUsername(username);

        if(!passwordEncoder.matches(password,accountContext.getAccount().getPassword()))
            throw new BadCredentialsException("Bad Password");

        // 해당 라인까지 왔다면 모든 인증절차를 거쳤다는 의미이다.
        UsernamePasswordAuthenticationToken authenticationToken
                = new UsernamePasswordAuthenticationToken(accountContext.getAccount().getPassword(),
                                                            null,
                                                            accountContext.getAuthorities());

        // 추가 인증 구현
        FormWebAuthenticationDetails formWebAuthenticationDetails = (FormWebAuthenticationDetails) authentication.getDetails();
        String secretKey = formWebAuthenticationDetails.getSecretKey();

        if(secretKey == null || !"secret".equals(secretKey))
            throw new InsufficientAuthenticationException("추가 인증 정보 불일치");

        return authenticationToken;
    }
}
