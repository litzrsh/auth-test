package me.litzrsh;

import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

@RestControllerAdvice
public class ExceptionHandlerAdvice {

    @ExceptionHandler(OAuth2AuthorizationCodeRequestAuthenticationException.class)
    public void exceptionHandler(OAuth2AuthorizationCodeRequestAuthenticationException e) {
        e.printStackTrace(System.err);
    }
}
