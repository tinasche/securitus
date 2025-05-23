package com.madner.securitus.resources;

import com.madner.securitus.services.AuthService;
import com.madner.securitus.user.ApiResponse;
import com.madner.securitus.user.LoginRequest;
import com.madner.securitus.user.RegisterRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthResource {
    private final AuthService authService;

    @PostMapping("/login")
    public ApiResponse login(@RequestBody LoginRequest request) {
        return authService.login(request);
    }

    @PostMapping("/register")
    public ApiResponse register(@RequestBody RegisterRequest request) {
        return authService.register(request);
    }
}
