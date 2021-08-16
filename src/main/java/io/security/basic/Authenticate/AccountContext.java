package io.security.basic.Authenticate;


import io.security.basic.Account.Account;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;

import java.util.Collection;

/**
 *  DB에서 찾은 사용자의 정보를 담는 객체이다.
 *  UserDetails 를 구현한 User 를 상속받았다.
 */
public class AccountContext extends User {

    // 인증 후에도 account를 담고 있어서 DB에 접근할 필요없이 지속적으로 사용할 수 있게한다.
    private Account account;

    // 부모 객체인 User를 세팅해주는 작업
    public AccountContext(Account account, Collection<? extends GrantedAuthority> authorities){
        super(account.getUsername(),account.getPassword(),authorities);
        this.account = account;
    }

    public Account getAccount(){
        return account;
    }
}
