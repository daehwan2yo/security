package io.security.basic.ajax;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.security.basic.Account.AccountDto;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.stereotype.Component;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class AjaxLoginProcessingFilter extends AbstractAuthenticationProcessingFilter {


    public AjaxLoginProcessingFilter(){
        super(new AntPathRequestMatcher("/api/login"));
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse) throws AuthenticationException, IOException, ServletException {
        ObjectMapper objectMapper = new ObjectMapper();
        if(!isAjax(httpServletRequest))
            throw new IllegalStateException("Authentication is not supported");

        AccountDto accountDto = objectMapper.readValue(httpServletRequest.getReader(),AccountDto.class);

        if(accountDto.getUsername() == null || accountDto.getPassword()==null)
            throw new IllegalStateException("ID or Password is empty");

        AjaxAuthenticationToken ajaxAuthenticationToken
                = new AjaxAuthenticationToken(accountDto.getUsername(),accountDto.getPassword());

        return getAuthenticationManager().authenticate(ajaxAuthenticationToken);

    }

    private boolean isAjax(HttpServletRequest request){
        if(request.getHeader("X-Requested-With").equals("XMLHttpRequest"))
            return true;
        return false;
    }

}

