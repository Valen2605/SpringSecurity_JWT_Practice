package com.valentina.SpringSecurityJWT.config;

import com.valentina.SpringSecurityJWT.service.JwtUtils;
import com.valentina.SpringSecurityJWT.service.OurUserDetailsService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
public class JWTAuthFilter extends OncePerRequestFilter {

    @Autowired
    private JwtUtils jwtUtils;

    @Autowired
    private OurUserDetailsService ourUserDetailsService;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {

        final String AUTH_HEADER = request.getHeader("Authorization"); // Nos servirá para extraer la autenticación.
        final String JWT_TOKEN;
        final String USER_EMAIL;

        if(AUTH_HEADER == null || AUTH_HEADER.isBlank()){
            filterChain.doFilter(request, response);
            return;
        }

        JWT_TOKEN = AUTH_HEADER.substring(7); // Se utiliza para eliminar la palabra bearer y el espacio que está antes del token
        USER_EMAIL = jwtUtils.extractUsername(JWT_TOKEN); // extrae el nombre de usuario (email)

        if(USER_EMAIL != null && SecurityContextHolder.getContext().getAuthentication() == null){

            UserDetails userDetails = ourUserDetailsService.loadUserByUsername(USER_EMAIL);

            if(jwtUtils.isTokenValid(JWT_TOKEN, userDetails)){
                SecurityContext securityContext = SecurityContextHolder.createEmptyContext();
                UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken(
                        userDetails, null, userDetails.getAuthorities()
                );
                token.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                securityContext.setAuthentication(token);
                SecurityContextHolder.setContext(securityContext);
            }
        }
        filterChain.doFilter(request, response);
    }
}
