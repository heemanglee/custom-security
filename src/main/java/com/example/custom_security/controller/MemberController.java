package com.example.custom_security.controller;

import com.example.custom_security.dto.LoginRequest;
import com.example.custom_security.dto.LoginResponse;
import com.example.custom_security.dto.RegisterRequest;
import com.example.custom_security.dto.RegisterResponse;
import com.example.custom_security.security.CustomUserDetails;
import com.example.custom_security.service.MemberService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.ResponseBody;

@Controller
@Slf4j
@RequiredArgsConstructor
public class MemberController {

    private final MemberService memberService;

    @GetMapping("/home")
    public String home(@AuthenticationPrincipal CustomUserDetails member) {
        if (member != null) {
            // member.email = test@test.com,
            // member.password = $2a$10$Q8NNVZ6jfvakrcJvWE1dIut7KYp9jNeaeUG5jR7hp85k2jiWUS8aK,
            // member.role = [CustomGrantedAuthority(role=ROLE_USER)]
            log.info("member.email = {}, member.password = {}, member.role = {}",
                member.getUsername(), member.getPassword(), member.getAuthorities());
        }

        return "index";
    }

    @GetMapping("/register")
    public String registerForm() {
        return "registerForm";
    }

    @PostMapping("/register")
    public String register(@ModelAttribute RegisterRequest request) {
        log.info("request = {}", request);
        RegisterResponse response = memberService.register(request);

        // response = RegisterResponse(id=1, email=test@test.com, password=$2a$10$Q8NNVZ6jfvakrcJvWE1dIut7KYp9jNeaeUG5jR7hp85k2jiWUS8aK, role=사용자)
        log.info("response = {}", response);

        return "redirect:/";
    }

    @GetMapping("/login")
    public String loginForm() {
        return "loginForm";
    }

    @PostMapping("/login")
    @ResponseBody
    public LoginResponse login(@ModelAttribute LoginRequest request) {
        log.info("request = {}", request);
        LoginResponse response = memberService.login(request);

        log.info("response = {}", response);
        return response; // return을 무시하고, security config에서 defaultSuccessUrl을 지정한 경로로 이동한다.
    }
}