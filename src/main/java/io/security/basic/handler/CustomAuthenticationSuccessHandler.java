package io.security.basic.handler;

import org.springframework.security.core.Authentication;
import org.springframework.security.web.DefaultRedirectStrategy;
import org.springframework.security.web.RedirectStrategy;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.security.web.savedrequest.SavedRequest;
import org.springframework.stereotype.Component;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Arrays;
import java.util.List;

@Component("authenticationSuccessHandler")
public class CustomAuthenticationSuccessHandler extends SimpleUrlAuthenticationSuccessHandler {

    private String[] canAccessAfterLogin = {"/","/mypage","/denied"};

    private RequestCache requestCache = new HttpSessionRequestCache();
    private RedirectStrategy redirectStrategy = new DefaultRedirectStrategy();

    // success 시 처리
    // 사용자가 이전에 이동하려던 페이지로 로그인이 성공하면 동적으로 이동하게 해준다.
    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
        // 로그인후에 정적으로 이동될 페이지 세팅
        setDefaultTargetUrl("/");

        SavedRequest savedRequest = requestCache.getRequest(request,response);

        // 사용자가 별도의 url 요청이 있는지 확인
        // 일부 허용 페이지를 설정해둬야함
        if(savedRequest != null &&
                Arrays.stream(canAccessAfterLogin)
                        .anyMatch(url->url.equals(savedRequest.getRedirectUrl())) )
            // savedRequest 내의 redirectUrl 로 redirectStrategy를 통해 재요청한다.
            redirectStrategy.sendRedirect(request,response,savedRequest.getRedirectUrl());

        // 없는 경우 기본 페이지로 정적으로 이동한다.
        else
            redirectStrategy.sendRedirect(request,response,getDefaultTargetUrl());
    }
}
