package com.example.jwt.jwt;

import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

// 스프링 시큐리티에 UsernamePasswordAuthenticationFilter가 있음
// /login 요청해서 username, password를 전송하면(post)
// UsernamePasswordAuthenticationFilter 필터가 동작을 함
// formLogin을 disable 했기 때문에 SecurityConfig에 등록해줌
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends UsernamePasswordAuthenticationFilter {
    private final AuthenticationManager authenticationManager;

    // /login 요청을 하면 로그인 시도를 위해서 실행되는 함수
    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
        System.out.println("JwtAuthenticationFilter.attemptAuthentication");
        
        // 1. username, password
        // 2. 로그인 시도 authenticationManager로 로그인 시도를 하면
        // PrincipalDetailsService의 loadUserByUsername()가 실행됨

        // 3. PrincipalDetails를 세션에 담음(권한 관리를 하기위함)

        // 4. JWT토큰을 만들어서 응답
        return super.attemptAuthentication(request, response);
    }
}
