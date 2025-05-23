package com.madner.securitus.services;

import com.madner.securitus.user.*;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class AuthService {
    private final AppUserRepository repository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final AuthenticationManager authenticationManager;

    public ApiResponse login(LoginRequest  request) {
        var user = repository.findByEmail(request.email())
                .orElseThrow();
        if (!passwordEncoder.matches(request.password(), user.getPassword())) {
            return new ApiResponse(null, "Credentials are incorrect", false);
        }
        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        request.email(),
                        request.password()
                )
        );
        var jwtToken = jwtService.generateToken(user);
        return new ApiResponse(jwtToken, "Login successful", true);
    }

    public ApiResponse register(RegisterRequest request) {
        var user = User.builder()
                .email(request.email())
                .password(passwordEncoder.encode(request.password()))
                .role(Role.USER)
                .lastname(request.lastname())
                .firstname(request.firstname())
                .build();
        User newUser = repository.save(user);
        return new ApiResponse(newUser, "User created zvakanaka", true);
    }
}
