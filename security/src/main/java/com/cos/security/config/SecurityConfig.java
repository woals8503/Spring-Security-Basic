package com.cos.security.config;

import com.cos.security.oauth.PrincipalOauth2UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;

//권한을 부여
@Configuration
@EnableWebSecurity
// 활성화 -> 스프링 시큐리티 필터(SecurityConfig)가 스프링 필터 체인에 등록이 된다.
// 그리고 CSRF protection 기능이 자동으로 활성화된다.
@EnableGlobalMethodSecurity(securedEnabled = true, prePostEnabled = true)
// -> secured 어노테이션 활성화 
// -> preAuthorize 어노테이션 활성화
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    private PrincipalOauth2UserService principalOauth2UserService;

    //해당 메소드의 리턴되는 오브젝트를 IoC로 등록해준다.
//    @Bean
//    public BCryptPasswordEncoder encodePwd() {
//        return new BCryptPasswordEncoder();
//    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.csrf().disable();  // 사이트간 요청 위조 비활성화 ( rest api 방식이라서 )
        http.authorizeRequests()
                .antMatchers("/user/**").authenticated()   // 이러한 주소가 들어오면 인증이 필요하다는걸 명시 {403은 접근 권한이 없다}
                .antMatchers("/manager/**").access("hasRole('ROLE_ADMIN') or hasRole('ROLE_MANAGER')")
                // manager로 접근하게되면 ROLE_ADMIN이나 ROLE_MANAGER권한이 있는 사람만 접근 가능하게 설정
                .antMatchers("/admin/**").access("hasRole('ROLE_ADMIN')")
                .anyRequest().permitAll()  // 위 세가지 주소가 아니면 누구나 허용
                // 그리고 권한이 없는(403) 페이지 요청시 login 페이지로 이동하게 설정 
                .and()
                .formLogin()    // manager를 입력하면 manager로 가고 admin을 입력하면 admin으로 간다
                .loginPage("/loginForm")
                .loginProcessingUrl("/login")
//                .usernameParameter("username2")   이렇게 지정할 경우 name="username2" 가능
                // /login 주소가 호출이 될 시 Security가 낚아채서 대신 로그인을 진행해준다.
                // 그렇기 때문에 controller에 /login을 만들지 않아도 된다.
                .defaultSuccessUrl("/")    // 그리고 메인페이지로 넘어가게 한다. logout시 / 로 넘어오는 디폴트값
                .and()  // 그리고
                .oauth2Login()
                .loginPage("/loginForm") // oauth 페이지나 일반 로그인 페이지나 똑같이 함
                // 구글 로그인이 완료된 뒤의 후처리가 필요하다.
                // 상황 -> manager를 입력 후 loginForm으로 이동하면 manager를 갖고있는 상태인데 세션이 없기 때문에?
                //        403 에러가 뜨게 된다. 그래서 후처리가 필요하다. ( Attribute 받아야함 )
                // Tip -> 구글로그인이 완료되면 코드를 받는 것이 아닌 Attribute(access 토큰 + 사용자 프로필 정보)를 한번에 받는다.
                .userInfoEndpoint()
                .userService(principalOauth2UserService); // 타입은 OAuth2User Service 타입이여야만한다.
    }
}
