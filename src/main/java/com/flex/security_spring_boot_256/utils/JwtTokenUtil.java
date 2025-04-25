package com.flex.security_spring_boot_256.utils;

import com.flex.security_spring_boot_256.providers.JwtTokenProvider;
import com.flex.security_spring_boot_256.providers.SecurityDetailsProvider;
import io.jsonwebtoken.Claims;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import java.util.Arrays;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

@Component
public class JwtTokenUtil {
    private static final long serialVersionUID = -2550185165626007488L;
    private static Logger logger = LogManager.getLogger(JwtTokenUtil.class);

    private SecurityDetailsProvider securityDetailsProvider;

    @Autowired
    public JwtTokenUtil(SecurityDetailsProvider securityDetailsProvider) {
        this.securityDetailsProvider = securityDetailsProvider;
    }

    public String getUsernameFromToken(String token) {
        return getClaimFromToken(token, Claims::getSubject);
    }


    public Date getExpirationDateFromToken(String token) {
        return getClaimFromToken(token, Claims::getExpiration);
    }

    public <T> T getClaimFromToken(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = getAllClaimsFromToken(token);
        return claimsResolver.apply(claims);
    }

    public Claims getAllClaimsFromToken(String token) {
        return JwtTokenProvider.getInstance().getClaims(token);
    }

    private Boolean isTokenExpired(String token) {
        final Date expiration = getExpirationDateFromToken(token);
        return expiration.before(new Date());
    }

    public String generateToken(UserDetails userDetails) {
        Map<String, Object> claims = new HashMap<>();
        return doGenerateToken(claims, userDetails.getUsername());
    }

    public String generateTokenWithExp(UserDetails userDetails, long millis, Map<String, Object> claims) {
        return JwtTokenProvider.getInstance().createToken(userDetails.getUsername(), claims, millis);
    }

    public String generateToken(Map<String, Object> claims, String subject) {
        return JwtTokenProvider.getInstance().createToken(subject, claims);
    }

    private String doGenerateToken(Map<String, Object> claims, String subject) {
        return JwtTokenProvider.getInstance().createToken(subject, claims);
    }

    public Boolean validateToken(String token, UserDetails userDetails) {
        final String username = getUsernameFromToken(token);
        return (username.equals(userDetails.getUsername()) && !isTokenExpired(token));
    }

    public Boolean validateToken(String token) {
        try {
            final String username = getUsernameFromToken(token);
            if ("SUPER_ADMIN".equals(username)) return !isTokenExpired(token);
            else if (securityDetailsProvider.getUserTypes().stream().anyMatch(username::equals)) {
                return !isTokenExpired(token);
            }
        } catch (Exception e) {
            logger.error("Error Validating Token !", e);
        }
        return false;
    }
}
