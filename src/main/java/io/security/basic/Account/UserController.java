package io.security.basic.Account;

import org.modelmapper.ModelMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;

@Controller
public class UserController {

    @Autowired
    UserService userService;
    @Autowired
    PasswordEncoder passwordEncoder;
    @Autowired
    ModelMapper modelMapper;

    @GetMapping("/mypage")
    public String myPage(){
        return "/user/myPage";
    }

    @GetMapping("/users")
    public String createUser(){
        return "/user/login/register";
    }

    @PostMapping("/users")
    public String createUser(AccountDto accountDto){
        Account account = modelMapper.map(accountDto,Account.class);
        String en_password = passwordEncoder.encode(account.getPassword());
        account.setPassword(en_password);
        userService.createUser(account);

        return "redirect:/";
    }

}
