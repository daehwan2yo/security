package io.security.basic.handler;

import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;
import org.springframework.stereotype.Component;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Component
public class CustomAuthenticationFailureHandler extends SimpleUrlAuthenticationFailureHandler {
    @Override
    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception) throws IOException, ServletException {
        // 기본 에어메시지 세팅
        String errorMessage = "Invaild username or password" ;

        // 인자로 들어온 exception의 종류에 따라 errorMessage변경
        if(exception instanceof BadCredentialsException)
            errorMessage = "bad password";
        else if(exception instanceof InsufficientAuthenticationException)
            errorMessage = "bad secret key";

        // 로그인 인증 실패 시 접근할 페이지 세팅 -> Controller 에서 GET으로 받아진다.
        // (따라서 Controller 에서 추가해줘야하며, SecurityConfig 에서 접근 권한도 바꿔줘야함)
        setDefaultFailureUrl("/login?error=true&exception="+errorMessage);

        // 후 처리는 기존 실패 handler 메서드에 맡김
        super.onAuthenticationFailure(request,response,exception);
    }
}
