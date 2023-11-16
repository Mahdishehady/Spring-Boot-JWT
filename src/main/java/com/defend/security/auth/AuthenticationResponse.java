package com.defend.security.auth;

import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
@JsonInclude(JsonInclude.Include.NON_EMPTY)//if user not enabled 2fa the secretImageUri that well be empty well not be send in the api.
public class AuthenticationResponse {

    private String token;
    private String error;
    private boolean mfaEnabled;
    private String secretImageUri;
}
