package kz.qbm.app.controller;

import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import kz.qbm.app.dto.auth.AuthRequest;
import kz.qbm.app.dto.auth.RegisterRequest;
import kz.qbm.app.service.AuthService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import javax.crypto.SecretKey;

@RestController
@RequiredArgsConstructor
@RequestMapping("/api/auth")
public class AuthController {
    // SERVICES
    private final AuthService authService;

    @PostMapping("/register")
    public ResponseEntity<?> registerUser(@RequestBody RegisterRequest registerRequest) {
        return authService.registerUser(registerRequest);
    }

    @PostMapping("/login")
    public ResponseEntity<?> loginUser(@RequestBody AuthRequest authRequest) {
        return authService.loginUser(authRequest);
    }

    @GetMapping
    public SecretKey asd() {
        return Keys.secretKeyFor(SignatureAlgorithm.HS512);
    }

    @GetMapping("/refresh")
    public ResponseEntity<?> refreshToken(@RequestParam String token) {
        return authService.getAccessTokenByRefreshToken(token);
    }
}
