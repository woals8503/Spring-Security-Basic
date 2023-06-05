package com.cos.security.auth;

import com.cos.security.model.User;
import com.cos.security.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;


// Authentication(입증) 생성
// 언제 발동되는가? -> Security 설정에서 .loginProcessingUrl("/login"); 으로 설정해놨기 때문에
// /login 요청이 올 경우 자동으로 UserDetailsService 타입으로 IoC 되있는 loadUserByUsername 함수가 실행된다.
// 이 service는 Authentication에 리턴된다
@Service
public class PrincipalDetailsService implements UserDetailsService {

    @Autowired
    private UserRepository userRepository;

    // Security session { Authentication(내부 UserDetails) }
    // 함수 종료시 @AuthenticationPrincipal 어노테이션이 만들어진다.
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        // html에서 이름을 username으로 통일해야함  -> name="username2" 라고 지정하면 동작 x
        User userEntity = userRepository.findByUsername(username);
        if(userEntity != null) {
            return new PrincipalDetails(userEntity);
        }
        return null;
    }
}
