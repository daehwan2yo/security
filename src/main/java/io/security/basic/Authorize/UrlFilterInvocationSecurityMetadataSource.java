package io.security.basic.Authorize;

import org.apache.coyote.Request;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.web.FilterInvocation;
import org.springframework.security.web.access.intercept.FilterInvocationSecurityMetadataSource;
import org.springframework.security.web.util.matcher.RequestMatcher;

import javax.servlet.http.HttpServletRequest;
import java.util.*;

public class UrlFilterInvocationSecurityMetadataSource implements FilterInvocationSecurityMetadataSource {

    private LinkedHashMap<RequestMatcher,List<ConfigAttribute>> requestMap = new LinkedHashMap<>();

    @Override
    public Collection<ConfigAttribute> getAttributes(Object o) throws IllegalArgumentException {
        // SecurityMetadataSource interface를 상속받아 사용하고, 해당 interface는 url 방식 뿐아니라 method 방식도 지원하므로,
        // Object 형식으로 객체를 매개받고 casting 하여 사용한다.
        HttpServletRequest request = ((FilterInvocation)o).getRequest();

        if(request!=null)
            for(Map.Entry<RequestMatcher,List<ConfigAttribute>> entry : )

    }

    @Override
    public Collection<ConfigAttribute> getAllConfigAttributes() {
        Set<ConfigAttribute> allAttributes = new HashSet<>();
        for(Map.Entry<RequestMatcher,List<ConfigAttribute>> entry : requestMap.entrySet())
            allAttributes.addAll(entry.getValue());

        return allAttributes;
    }

    @Override
    public boolean supports(Class<?> aClass) {
        return FilterInvocation.class.isAssignableFrom(aClass);
    }
}
