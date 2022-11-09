package com.example.jwt.jwt;

public interface JwtProperties {
    int EXPIRATION_TIME = 60000*3;
    String TOKEN_PREFIX = "Bearer ";
    String HEADER_STRING = "Authorization";
    String SECRET = "shin";
}
