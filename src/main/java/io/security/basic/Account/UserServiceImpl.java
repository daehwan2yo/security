package io.security.basic.Account;


import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service("userService")
public class UserServiceImpl implements UserService {

    @Autowired
    AccountRepository accountRepository;


    @Transactional
    @Override
    public void createUser(Account account) {
        accountRepository.save(account);
    }
}
