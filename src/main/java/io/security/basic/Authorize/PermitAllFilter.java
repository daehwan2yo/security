package io.security.basic.Authorize;

import org.springframework.security.access.SecurityMetadataSource;
import org.springframework.security.access.intercept.InterceptorStatusToken;
import org.springframework.security.web.FilterInvocation;
import org.springframework.security.web.access.intercept.FilterInvocationSecurityMetadataSource;
import org.springframework.security.web.access.intercept.FilterSecurityInterceptor;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

public class PermitAllFilter extends FilterSecurityInterceptor {
    private static final String FILTER_APPLIED = "__spring_security_filterSecurityInterceptor_filterApplied";
    private boolean observeOncePerRequest = true;

    private List<RequestMatcher> permitAllRequestMatchers = new ArrayList<>();

    // 실제 인가처리를 하기 전에 permitAll을 해주는 로직을 구현한다.
    @Override
    protected InterceptorStatusToken beforeInvocation(Object object) {

        //FilterInvocation은 사용자 요청정보를 가져올 수있다.
        HttpServletRequest request = ((FilterInvocation)object).getRequest();

        for(RequestMatcher requestMatcher : permitAllRequestMatchers){
            if(requestMatcher.matches(request))
                return null;
        }

        // 만약 사용자 요청이 permitAll 의 자원과 맞지 않는다면 부모의 before처리를 따라주면 된다.
        return super.beforeInvocation(object);
    }

    // 생성자로 부터 여러개의 permitAll 을 해줄 자원 정보를 받아와 List 에 추가해준다.
    public PermitAllFilter(String...permitAllResources){
        for(String resource : permitAllResources){
            permitAllRequestMatchers.add(new AntPathRequestMatcher(resource));
        }
    }

    public void invoke(FilterInvocation filterInvocation) throws IOException, ServletException {
        if (this.isApplied(filterInvocation) && this.observeOncePerRequest) {
            filterInvocation.getChain().doFilter(filterInvocation.getRequest(), filterInvocation.getResponse());
        } else {
            if (filterInvocation.getRequest() != null && this.observeOncePerRequest) {
                filterInvocation.getRequest().setAttribute("__spring_security_filterSecurityInterceptor_filterApplied", Boolean.TRUE);
            }

            InterceptorStatusToken token = super.beforeInvocation(filterInvocation);

            try {
                filterInvocation.getChain().doFilter(filterInvocation.getRequest(), filterInvocation.getResponse());
            } finally {
                super.finallyInvocation(token);
            }

            super.afterInvocation(token, (Object)null);
        }
    }

    private boolean isApplied(FilterInvocation filterInvocation) {
        return filterInvocation.getRequest() != null && filterInvocation.getRequest().getAttribute("__spring_security_filterSecurityInterceptor_filterApplied") != null;
    }

}
