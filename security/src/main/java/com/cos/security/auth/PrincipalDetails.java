package com.cos.security.auth;

// Security가 /login 주소 요청이 오면 낚아채서 로그인을 진행시킨다.
// 로그인 진행이 완료되면 시큐리티 session을 만들어준다. ( Security ContextHolder )라는 키값에 session 정보를 저장한다.
// Security가 만든 세션 Object는 정해져있는데 무조건 Authentication 타입의 객체여야한다.
// Authentication 안에 User 정보가 있어야 한다. 이것도 클래스가 정해져있다.
// User 오브젝트 타입 => UserDetails 타입 객체여야한다.

// 즉 Security Session 영역에 정보를 저장하는데 이 영역에는 Authentication 타입 객체만 들어갈 수 있으며,
// Authentication안에 들어가는 정보의 타입은 UserDetatils(PrincipalDetails)
// PrincipalDetails가 UserDetails를 구현하게 되면 UserDetails와 같은 타입이 된다.

import com.cos.security.model.User;
import lombok.Data;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.core.user.OAuth2User;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Map;

@Data
public class PrincipalDetails implements UserDetails, OAuth2User {
    
    // Authentication 객체 안에 들어가는 정보는 UserDetails 타입이여야 함으로
    // UserDetails를 상속하여 구현체로 받아들임 ( 즉 같은 타입이 됨 )
    
    private User user;  // 컴포지션
    private Map<String, Object> attributes;

    //일반 로그인
    public PrincipalDetails(User user) {
        this.user = user;
    }

    // OAuth 로그인    ( 유저와 attribute를 둘다 가지고 있음 )
    public PrincipalDetails(User user, Map<String, Object> attributes) {
        this.user = user;
        this.attributes = attributes;
    }

    //==========OAuth 구현 메소드======================
    @Override
    public Map<String, Object> getAttributes() {
        return attributes;
    }

    @Override
    public String getName() {
        return null;
    }
    //===============================================

    //==========UserDetails 구현 메소드===========

    // 해당 User의 권한을 리턴하는 곳
    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
//        user.getRole(); // String타입이라 이것을 리턴할 수는 없다.
        // 그래서 타입을 만들어줘야한다.
        Collection<GrantedAuthority> collect = new ArrayList<>();
        collect.add((GrantedAuthority) user::getRole);
        // GrantedAuthority 생성자를 만들어 오버라이드한 메소드로 user.getRole()를 호출하여 리턴
        return collect;
    }

    @Override
    public String getPassword() {
        return user.getPassword();
    }

    @Override
    public String getUsername() {
        return user.getUsername();
    }

    //계정 만료
    @Override
    public boolean isAccountNonExpired() {
        return true;
    }


    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    // 계정 비밀번호가 1년이 지났니?, 너무 오래사용한건 아닌가?
    @Override
    public boolean isCredentialsNonExpired() {
        return true;    // 아니오 ( true )
    }

    //계정이 활성화 되있는가?
    @Override
    public boolean isEnabled() {
        // 사이트에서 1년동안 회원이 로그인을 안하면 휴먼 계정으로 하기로 했다면 User모델에
//        user.getLoginDate();
        // 현재시간 - 로그인 시간 -> 1년 초과할 시 return false
        return true;    // 아니오 ( true )
    }
    //========================================
}
