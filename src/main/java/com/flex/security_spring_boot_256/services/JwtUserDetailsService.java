package com.flex.security_spring_boot_256.services;

import com.flex.security_spring_boot_256.AuthorizationException;
import com.flex.security_spring_boot_256.providers.SecurityDetailsProvider;
import com.flex.security_spring_boot_256.utils.JwtTokenUtil;
import io.jsonwebtoken.Claims;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.ArrayList;

@SuppressWarnings("Duplicates")
@Service
public class JwtUserDetailsService implements UserDetailsService {
    private static Logger logger = LogManager.getLogger(JwtUserDetailsService.class);

    @Autowired
    protected JwtTokenUtil jwtTokenUtil;

    private final SecurityDetailsProvider securityDetailsProvider;

    @Autowired
    public JwtUserDetailsService(SecurityDetailsProvider securityDetailsProvider) {
        this.securityDetailsProvider = securityDetailsProvider;
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {

        if (securityDetailsProvider.getUserTypes().stream().anyMatch(username::equals)) {
            return new User(username, "EDv+UY+Yp1Ccp533SPtFew==", new ArrayList<>());
        }
        throw new UsernameNotFoundException("User not found with username: " + username);
    }

    public Claims authenticate(HttpServletRequest request, HttpServletResponse response)
            throws AuthorizationException {
        String requestTokenHeader = request.getHeader("Authorization");

        String jwtToken = null;

        if (requestTokenHeader != null && requestTokenHeader.startsWith("Bearer ")) {
            jwtToken = requestTokenHeader.substring("Bearer ".length());
        } else {
            logger.warn("JWT Token does not begin with Bearer String");
        }

        if (jwtTokenUtil.validateToken(jwtToken)) {
            return jwtTokenUtil.getAllClaimsFromToken(jwtToken);
        }
        throw new AuthorizationException("You are not allowed here");
    }
}
