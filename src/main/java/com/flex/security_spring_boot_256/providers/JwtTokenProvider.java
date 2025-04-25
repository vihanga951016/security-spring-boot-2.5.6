package com.flex.security_spring_boot_256.providers;

import com.flex.security_spring_boot_256.AuthorizationException;
import io.jsonwebtoken.*;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.beans.factory.annotation.Autowired;

import javax.servlet.http.HttpServletRequest;
import java.util.Base64;
import java.util.Date;
import java.util.Map;

public class JwtTokenProvider {

    private static final String secretKey = Base64.getEncoder()
            .encodeToString(SecurityDetailsProvider.getEncodeKey()
                    .getBytes());
    private static JwtTokenProvider instance;

    public static JwtTokenProvider getInstance() {
        if (instance == null) {
            instance = new JwtTokenProvider();
        }
        return instance;
    }

    private static final Logger logger = LogManager.getLogger(JwtTokenProvider.class);

    public String createToken(String username, Map<String, Object> claimMap) {

        Claims claims = Jwts.claims().setSubject(username);
        logger.debug("Token generating for subject >> " + username);
        if (claimMap != null) {
            for (String key : claimMap.keySet()) {
                claims.put(key, claimMap.get(key));
            }
        }

        // 24h -> h * min * sec * millis
        long validityInMilliseconds = 24 * 60 * 60 * 1000;
        return getToken(username, validityInMilliseconds+   new Date().getTime(), claims);
    }

    public String createToken(String username, Map<String, Object> claimMap, long validityInMillis) {

        Claims claims = Jwts.claims().setSubject(username);
        logger.debug("Token generating for subject >> " + username + " | validity millis " + validityInMillis);
        if (claimMap != null) {
            for (String key : claimMap.keySet()) {
                claims.put(key, claimMap.get(key));
            }
        }

        return getToken(username, validityInMillis, claims);
    }

    private String getToken(String username, long validityInMillis, Claims claims) {

        Date validity = new Date( validityInMillis);
        logger.debug("Token validate until " + validity);

        String token = Jwts.builder()
                .setClaims(claims)
                .setIssuer("ts-queue-edge")
                .setIssuedAt(new Date())
                .setExpiration(validity)
                .signWith(SignatureAlgorithm.HS256, secretKey)
                .compact();
        logger.debug("Token generated for username >> " + username);

        return token;
    }

    public String resolveToken(HttpServletRequest req) {
        String headerToken = req.getHeader("Authorization");
        if (headerToken != null && headerToken.startsWith("Bearer ")) {
            logger.info("Bearer Token Authorization");
            return headerToken.substring("Bearer ".length());
        }
        headerToken = req.getHeader("Bearer ");
        if (headerToken != null && !headerToken.isEmpty()) {
            logger.info("X-AUTH-TOKEN Token");
            return headerToken;
        }
        logger.info("Token is null or empty");
        return null;
    }

    public String getUsername(String token) {
        return Jwts.parser()
                .setSigningKey(secretKey)
                .parseClaimsJws(token)
                .getBody()
                .getSubject();
    }

    public Claims getClaims(String jwt) throws ExpiredJwtException {
        //This line will throw an exception if it is not a signed JWS (as expected)
        return Jwts.parser()
                .setSigningKey(secretKey)
                .parseClaimsJws(jwt)
                .getBody();
    }

    public boolean validateToken(String token) throws AuthorizationException {
        try {
            Jwts.parser().setSigningKey(secretKey).parseClaimsJws(token);
            return true;
        } catch (JwtException | IllegalArgumentException e) {
            logger.error("Signature verification failed. >> " + e.getMessage(), e);
            throw new AuthorizationException(e);
        }
    }
}
