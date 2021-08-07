package io.security.basic;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class SecurityController {

    @GetMapping("/loginPage")
    public String loginPage(){
        return "login";
    }
}
