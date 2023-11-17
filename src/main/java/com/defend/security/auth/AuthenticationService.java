package com.defend.security.auth;

import com.defend.security.config.JwtService;
import com.defend.security.tfs.TowFactorAuthenticationService;
import com.defend.security.user.Role;
import com.defend.security.user.User;
import com.defend.security.user.UserRespository;
import jakarta.persistence.EntityNotFoundException;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;


@Service
@RequiredArgsConstructor
public class AuthenticationService {
    private final UserRespository repository;
    private final JwtService jwtService;

    private final PasswordEncoder passwordEncoder;
    private final AuthenticationManager authenticationManager;
    private final TowFactorAuthenticationService tfaService;


    public AuthenticationResponse register(RegisterRequest request) {
        try {
            //Gards
            if (request.getPassword() == null) throw new Exception("Password is required");
            else {
                if (repository.existsByEmail(request.getEmail())) {
                    throw new IllegalStateException("User exists (:>");
                }

                var user = User.builder().firstname(request.getFirstname()).lastname(request.getLastname()).email(request.getEmail()).password(passwordEncoder.encode(request.getPassword())).role(Role.USER).mfaEnabled(request.isMfaEnabled()).build();

                if (request.isMfaEnabled())
                    user.setSecret(tfaService.generateNewSecret());
                var savedUser = repository.save(user);

                var jwtToken = jwtService.generateToken(user);

                return AuthenticationResponse.builder().token(jwtToken).secretImageUri(tfaService.generateQrCodeImageUri(user.getSecret())).mfaEnabled(user.isMfaEnabled()).build();
            }
        } catch (Exception ex) {
            return new AuthenticationResponse(null, null, false, ex.getMessage());
        }
    }

    public AuthenticationResponse authenticate(AuthenticationRequest request) {
        try {
            authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(request.getEmail(), request.getPassword()
                    //check if user entered and if not it will throw an exception
            ));
            var user = repository.findByEmail(request.getEmail()).orElseThrow();
            var jwtToken = jwtService.generateToken(user);
            if (user.isMfaEnabled()) {
                return AuthenticationResponse.builder()
                        .token(jwtToken)
                        .mfaEnabled(true)
                        .build();
            }
            return AuthenticationResponse.builder()
                    .token(jwtToken)
                    .mfaEnabled(false)
                    .build();

     } catch (Exception ex) {
            return new AuthenticationResponse(null, null, false, ex.getMessage());
        }
    }

    public AuthenticationResponse verifyCode(VerificationRequest verificationRequest) {

        User user = repository.findByEmail(verificationRequest.getEmail())
                .orElseThrow(() -> new EntityNotFoundException
                        (String.format("No user found  with %s", verificationRequest.getEmail())));
    if(tfaService.isOtpNotValid(user.getSecret(),verificationRequest.getCode()))
    {
        throw new BadCredentialsException("Code is not correct");

    }
    var jwt =jwtService.generateToken(user);

return AuthenticationResponse.builder()
        .token(jwt)
        .mfaEnabled(user.isMfaEnabled())
        .build();

    }
}
