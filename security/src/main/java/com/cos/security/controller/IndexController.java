package com.cos.security.controller;

import com.cos.security.auth.PrincipalDetails;
import com.cos.security.model.User;
import com.cos.security.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.annotation.Secured;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.ResponseBody;

@Controller
public class IndexController {

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private BCryptPasswordEncoder bCryptPasswordEncoder;

    // 일반 자사 회원 정보 가져오기
    @GetMapping("/test/login")
    public @ResponseBody String loginTest(
            Authentication authentication,  // 로그인 하면 UserDetails가 Authentication에 들어온다.
            @AuthenticationPrincipal PrincipalDetails userDetails) { // 어노테이션으로 하는 방식이 더 편하다.
        // DI하면 Authentication안에 Principal이 있다.
        // Principal은 Object타입이기 때문에 PrincipalDetails로 다운 캐스팅 하여
        System.out.println("/test/login ============");
        PrincipalDetails principalDetails = (PrincipalDetails) authentication.getPrincipal();
        System.out.println("authentication : " + principalDetails.getUser());

        System.out.println("userDetails : " + userDetails.getUser());

        // 즉 회원 엔티티 정보를 가져오는 작업
        return "세션 정보 확인하기";
    }

    //  구글 로그인하여 세션의 회원정보를 가져오는 작업 중 ClassCastException 에러 해결법
    // OAuth 회원 세션 정보 가져오기
    @GetMapping("/test/oauth/login")
    public @ResponseBody String testOAuthLogin(
            Authentication authentication,// OAuth 로그인 시 OAuth2User가 Authentication에 들어온다.
            @AuthenticationPrincipal OAuth2User oAuth) {    // 어노테이션 방법이 더 편함
        System.out.println("/test/login ============");
        OAuth2User oAuth2User = (OAuth2User) authentication.getPrincipal();
        System.out.println("authentication : " + oAuth2User.getAttributes());
        System.out.println("oauth2User : " + oAuth.getAttributes());
        return "OAuth 세션 정보 확인하기";
    }

    @GetMapping({"", "/"})
    public String index() {
        //머스테치
        return "index";
    }

    // OAuth 로그인을 해도 PrincipalDetails
    // 일반 로그인도 PrincipalDetails
    // 즉 위처럼 따로 분리할 필요가 없다.
    @GetMapping("/user")
    public @ResponseBody String user(@AuthenticationPrincipal PrincipalDetails principalDetails) {
        System.out.println("principalDetails = " + principalDetails.getUser());
        return "user";
    }

    @GetMapping("/admin")
    public @ResponseBody String admin() {
        return "admin";
    }

    @GetMapping("/manager")
    public @ResponseBody String manager() {
        return "manager";
    }

    // 스프링 시큐리티가 해당 주소를 낚아 채버린다. -> SecurityConfig 파일 생성 후 작동 안함
    @GetMapping("/loginForm")
    public String loginForm() {
        return "loginForm";
    }

    //회원가입 할 수 있는 페이지
    @GetMapping("/joinForm")
    public String joinForm() {
        return "joinForm";
    }

    //실제 회원가입
    @PostMapping("/join")
    public String join(User user) {
        user.setRole("ROLE_USER");
        userRepository.save(user);  // 회원가입 잘됨.
        // 하지만 시큐리티로 로그인을 할 수 없다. 이유는 패스워드가 암호화가 안됬기 때문이다.
        String rawPassword = user.getPassword();
        String encPassword = bCryptPasswordEncoder.encode(rawPassword); // 비밀번호 암호화
        user.setPassword(encPassword);  // 인코딩된 패스워드를 넣고
        userRepository.save(user);      // 저장
        return "redirect:/loginForm";
    }
    
    //ex) 관리자 페이지같은 관리자 권한이 있는 계정만 접근 가능할 때 사용
    @Secured("ROLE_ADMIN")  // 이렇게 설정할 경우 ROLE_ADMIN 권한이 있는 계정만 접근 가능하다.
    @GetMapping("/info")
    public @ResponseBody String info() {
        return "개인정보";
    }

    @PreAuthorize("hasRole('ROLE_MANAGER') or hasRole('ROLE_ADMIN')") // 이 data라는 메소드가 실행되기 직전에 실행된다.
    @GetMapping("/data")
    public @ResponseBody String data() {
        return "data 정보";
    }
}
