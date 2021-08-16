package io.security.basic.Authenticate;

import io.security.basic.Account.Account;
import io.security.basic.Account.AccountRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

import java.util.ArrayList;
import java.util.List;

/**
 * 입력받은 사용자의 정보를 통해 DB로부터 사용자의 정보를 불러오는 객체
 * UserDetialsService interface 구현을 통해
 * UserDetails 를 구현한 User 객체를 상속받은 AccountContext 객체를 반환한다.
 */

// Bean으로 등록하여 인증시 사용한다.
public class CustomUserDetailsService implements UserDetailsService {

    @Autowired
    private AccountRepository accountRepository;

    // 사용자로 부터 입력받은 username을 통해 DB에 접근해서 사용자 정보를 AccountContext에 담는다.
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        Account account = accountRepository.findByUsername(username)
                .orElseThrow(()-> new UsernameNotFoundException("일치하는 회원정보가 없습니다."));

        // 사용자의 권한 내역들을 불러온다.
        // 아직은 Account 객체에서 Role 이 String 형식으로 되어있기 때문에 직접 주입한다.
        //  GrantAuthority interface를 구현한 SimpleGrantAuthority 를 매개로 한다
        List<GrantedAuthority> roles = new ArrayList<>();
        roles.add(new SimpleGrantedAuthority("ROLE_USER"));

        AccountContext accountContext = new AccountContext(account,roles);

        return accountContext;

    }
}
