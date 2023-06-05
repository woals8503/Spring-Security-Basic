package com.cos.security.oauth;

import com.cos.security.auth.PrincipalDetails;
import com.cos.security.model.User;
import com.cos.security.provider.GoogleUserInfo;
import com.cos.security.provider.NaverUserInfo;
import com.cos.security.provider.OAuth2UserInfo;
import com.cos.security.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

import java.util.Map;

@Service
public class PrincipalOauth2UserService extends DefaultOAuth2UserService {

    @Autowired
    private CustomBCryptPasswordEncoder bCryptPasswordEncoder;

    @Autowired
    private UserRepository userRepository;

    // 구글로 부터 받은 userRequest 데이터에 대한 후처리 함수
    // 함수 종료시 @AuthenticationPrincipal 어노테이션이 만들어진다.
    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
        // 어떤 OAuth로 로그인 했는지 확인 가능
        System.out.println("getClientRegistration : " + userRequest.getClientRegistration());
        System.out.println("getRegistrationId : " + userRequest.getClientRegistration().getRegistrationId());
        System.out.println("getClientId : " + userRequest.getClientRegistration().getClientId());
        System.out.println("getClientName : " + userRequest.getClientRegistration().getClientName());
        System.out.println("getClientSecret : " + userRequest.getClientRegistration().getClientSecret());
        System.out.println("getAccessToken : " + userRequest.getAccessToken());
        System.out.println("getTokenValue : " + userRequest.getAccessToken().getTokenValue());
        // 구글로그인 버튼 클릭 -> 구글 로그인 창 -> 로그인 완료 -> code를 리턴(OAuth-Client 라이브러리가 받음) -> code를 통하여 Access토큰 요청
        // 위의 단계까지가 userRequest 정보
        // userRequest 정보 -> loadUser함수 호출 -> ( 구글로 부터 ) 회원 프로필을 받을 수 있음.
        System.out.println("getAttributes : " + super.loadUser(userRequest).getAttributes());
        System.out.println("getAdditionalParameters : " + userRequest.getAdditionalParameters());

        OAuth2User oAuth2User = super.loadUser(userRequest);

        OAuth2UserInfo oAuth2UserInfo = null;
        if(userRequest.getClientRegistration().getRegistrationId().equals("google")) {
            System.out.println("구글 로그인 요청");
            oAuth2UserInfo = new GoogleUserInfo(oAuth2User.getAttributes());
        }else if(userRequest.getClientRegistration().getRegistrationId().equals("naver")) {
            System.out.println("네이버 로그인 요청");
            // 네이버는 response키를 가진 Map 형태 안에 attribute를 가지고 있기 때문에 아래와 같이 작성함
            oAuth2UserInfo = new NaverUserInfo((Map<String, Object>) oAuth2User.getAttributes().get("response"));
            // 하지만 yml에서 user-name-attribute: response를 설정하였기 때문에 아래와 같이 작성 가능
//            oAuth2UserInfo = new NaverUserInfo((Map) oAuth2User.getAttributes());
        }

        String provider = oAuth2UserInfo.getProvider();    // google
        String providerId = oAuth2UserInfo.getProviderId(); // google의 sub(기본키)
        String email = oAuth2UserInfo.getEmail();
        String username = provider + "_" + providerId;  // google_기본키
        String password = bCryptPasswordEncoder.encode("겟인데어");
        String role = "ROLE_USER";

        User user = userRepository.findByUsername(username);

        if(user == null) {
            System.out.println("OAuth 로그인이 최초입니다.");
            user = user.builder()
                    .username(username)
                    .password(password)
                    .email(email)
                    .role(role)
                    .provider(provider)
                    .providerId(providerId)
                    .build();
            userRepository.save(user);
        }else {
            System.out.println("이미 로그인 되있습니다.");
        }

        return new PrincipalDetails(user, oAuth2User.getAttributes());
    }
}
