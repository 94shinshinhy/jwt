package com.example.jwt.filter;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.PrintWriter;

public class MyFilter3 implements Filter {
    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        HttpServletRequest req = (HttpServletRequest)request;
        HttpServletResponse res = (HttpServletResponse)response;

        // 토큰 : id, pw 정상적으로 들어와서 로그인이 완료가 되면 토큰을 만들어주고 응답을 해줌
        // 요청할 때 마다 header에 Authrization에 value값으로 토큰을 가지고 옴
        // 토큰이 넘어오면 내가 만든 토큰이 맞는지 검증(RSA, HS256)
        if(req.getMethod().equals("POST")){
            //System.out.println("POST 요청");
            String headerAuth = req.getHeader("Authorization");
            //System.out.println("headerAuth : " + headerAuth);
            //System.out.println("필터3");
            if(headerAuth.equals("shin")){
                chain.doFilter(req, res);
            } else {
                PrintWriter out = res.getWriter();
                out.println("인증안됨");
            }
        }
    }
}
