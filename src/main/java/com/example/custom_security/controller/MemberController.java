package com.example.custom_security.controller;

import com.example.custom_security.dto.GetUserInfoResponse;
import com.example.custom_security.dto.LoginRequest;
import com.example.custom_security.dto.LoginResponse;
import com.example.custom_security.dto.RegisterRequest;
import com.example.custom_security.dto.RegisterResponse;
import com.example.custom_security.entity.Member;
import com.example.custom_security.security.CurrentUser;
import com.example.custom_security.service.MemberService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.ResponseBody;

@Controller
@Slf4j
@RequiredArgsConstructor
public class MemberController {

    private final MemberService memberService;

    @GetMapping("/home")
    public String home(@CurrentUser Member member) {
        if (member != null) {
            // member.email = test@test.com,
            // member.password = $2a$10$Q8NNVZ6jfvakrcJvWE1dIut7KYp9jNeaeUG5jR7hp85k2jiWUS8aK,
            // member.role = [CustomGrantedAuthority(role=ROLE_USER)]
//            log.info("member.email = {}, member.password = {}, member.role = {}, member.member = {}",
//                member.getUsername(), member.getPassword(), member.getAuthorities(), member.getMember());

            log.info("member.email = {}, member.password = {}, member.role = {}", member.getEmail(), member.getPassword(), member.getRole());
        }

        return "index";
    }

    @GetMapping("/register")
    public String registerForm() {
        return "registerForm";
    }

    @PostMapping("/register")
    @ResponseBody
    public RegisterResponse register(@RequestBody RegisterRequest request) {
        log.info("request = {}", request);
        RegisterResponse response = memberService.register(request);

        // response = RegisterResponse(id=1, email=test@test.com, password=$2a$10$Q8NNVZ6jfvakrcJvWE1dIut7KYp9jNeaeUG5jR7hp85k2jiWUS8aK, role=사용자)
        log.info("response = {}", response);
        return response;
    }

    @GetMapping("/login")
    public String loginForm() {
        return "loginForm";
    }

    @PostMapping("/login")
    @ResponseBody
    public LoginResponse login(@RequestBody LoginRequest request) {
        log.info("request = {}", request);
        LoginResponse response = memberService.login(request);

        log.info("response = {}", response);
        return response; // return을 무시하고, security config에서 defaultSuccessUrl을 지정한 경로로 이동한다.
    }

    @GetMapping("/authorization-user")
    public String authorizationUser() {
        return "authorizationUser";
    }

    @GetMapping("/authorization-admin")
    public String authorizationAdmin() {
        return "authorizationAdmin";
    }

    @GetMapping("/me")
    @ResponseBody
    public GetUserInfoResponse me(@CurrentUser Member member) {
        return GetUserInfoResponse.of(member);
    }
}
