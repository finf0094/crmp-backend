package kz.qbm.app.service;

import kz.qbm.app.Repository.UserRepository;
import kz.qbm.app.config.CustomUserDetails;
import kz.qbm.app.config.CustomUserDetailsService;
import kz.qbm.app.dto.auth.AuthRequest;
import kz.qbm.app.dto.auth.AuthResponse;
import kz.qbm.app.dto.auth.RegisterRequest;
import kz.qbm.app.dto.user.UserResponse;
import kz.qbm.app.entity.User;
import kz.qbm.app.exception.AuthenticationException;
import kz.qbm.app.exception.NotFoundException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.web.client.HttpClientErrorException;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

@Slf4j
@Service
@RequiredArgsConstructor
public class AuthService {

    // REPOSITORIES
    private final UserRepository userRepository;

    // SERVICES
    private final JwtService jwtService;
    private final RoleService roleService;
    private final CustomUserDetailsService customUserDetailsService;

    // UTILS
    private final AuthenticationManager authenticationManager;
    private final PasswordEncoder passwordEncoder;

    // TOKENS WHICH SAVE IN MEMORY
    private final Map<String, String> userRefreshTokenMap = new HashMap<>();


    public ResponseEntity<?> registerUser(RegisterRequest registerRequest) {

        if (userRepository.findByEmail(registerRequest.getEmail()).isPresent()) {
            throw new AuthenticationException(
                    String.format("Пользователь с почтой '%s' уже существует", registerRequest.getEmail()),
                    HttpStatus.BAD_REQUEST
            );
        }

        if (userRepository.findByItin(registerRequest.getItin()).isPresent()) {
            throw new AuthenticationException(
                    String.format("Пользователь с ИИН '%s' уже существует", registerRequest.getEmail()),
                    HttpStatus.BAD_REQUEST
            );
        }

        User user = User.builder()
                .itin(registerRequest.getItin())
                .email(registerRequest.getEmail())
                .roles(List.of(roleService.findByName("ROLE_USER")))
                .firstname("")
                .lastname("")
                .password(passwordEncoder.encode(registerRequest.getPassword()))
                .build();

        userRepository.save(user);


        return ResponseEntity.status(HttpStatus.CREATED).body("USER SUCCESSFULLY CREATED");
    }


    public ResponseEntity<?> loginUser(AuthRequest authRequest) {

            try {
                authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(
                        authRequest.getItin(), authRequest.getPassword()
                ));
            }  catch (BadCredentialsException e) {
                throw new AuthenticationException("Пароль неправильный", HttpStatus.UNAUTHORIZED);
            }

                CustomUserDetails userDetails = customUserDetailsService.loadUserByUsername(authRequest.getItin());

                Authentication authentication = new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
                SecurityContextHolder.getContext().setAuthentication(authentication);

                String accessToken = jwtService.generateAccessToken(userDetails);
                String refreshToken = jwtService.generateRefreshToken(userDetails);

                userRefreshTokenMap.put(userDetails.getItin(), refreshToken);

                UserResponse userResponse = createUserResponse(userDetails);

                AuthResponse authResponse = AuthResponse.builder()
                        .access_token(accessToken)
                        .refresh_token(refreshToken)
                        .userInfo(userResponse)
                        .build();

                return ResponseEntity.ok(authResponse);
    }

    public ResponseEntity<?> getAccessTokenByRefreshToken(String refreshToken) {
        String itin = jwtService.getRefreshTokenItin(refreshToken);
        if (jwtService.isRefreshTokenValid(refreshToken) && userRefreshTokenMap.containsKey(itin)) {

            User user = userRepository.findByItin(itin).orElseThrow(
                    () -> new NotFoundException(String.format("User with itin %s not found", itin))
            );

            CustomUserDetails userDetails = new CustomUserDetails(
                    user.getItin(),
                    user.getPassword(),
                    user.getEmail(),
                    user.getRoles().stream()
                            .map(role -> new SimpleGrantedAuthority(role.getName()))
                            .collect(Collectors.toList())
            );

            String accessToken = jwtService.generateAccessToken(userDetails);

            UserResponse userResponse = createUserResponse(userDetails);

            AuthResponse authResponse = AuthResponse.builder()
                    .access_token(accessToken)
                    .refresh_token(refreshToken)
                    .userInfo(userResponse)
                    .build();

            return ResponseEntity.ok(authResponse);

        } else {
            throw new AuthenticationException("Invalid refresh token", HttpStatus.UNAUTHORIZED);
        }
    }

    private UserResponse createUserResponse(CustomUserDetails customUserDetails) {
        List<String> roleList = customUserDetails.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .toList();
        return UserResponse.builder()
                .email(customUserDetails.getEmail())
                .itin(customUserDetails.getItin())
                .roles(roleList)
                .build();
    }
}
