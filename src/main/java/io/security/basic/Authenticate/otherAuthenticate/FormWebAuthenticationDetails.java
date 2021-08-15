package io.security.basic.Authenticate.otherAuthenticate;

import lombok.Getter;
import org.springframework.security.web.authentication.WebAuthenticationDetails;

import javax.servlet.http.HttpServletRequest;

@Getter
public class FormWebAuthenticationDetails extends WebAuthenticationDetails {
    String secretKey;

    public FormWebAuthenticationDetails(HttpServletRequest request) {
        super(request);
        secretKey = request.getParameter("secretKey");
    }


}
