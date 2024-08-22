package com.uzay.security.jwt;

import com.uzay.security.modal.Roles;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.util.Date;

@Service
public class JwtService {
    public String secretKey ="EamB0+77svkZ+mrRq7LBrNGlnKuwMV01Aqs0mtZMShEQJe8wEruDBTgxruvezxqUT20x0bhzT40JJMBEUr3rIg==";

    public String generateToken(UserDetails userDetails){
        return Jwts.builder()
                .subject(userDetails.getUsername())
                .signWith(getSignKey(secretKey))
                .expiration(new Date(System.currentTimeMillis() + 1000 * 60 * 60 * 24 * 7))
                .issuedAt(new Date(System.currentTimeMillis()))
                .claim("role", Roles.ROLE_USER)
                .compact();
    }

    public SecretKey getSignKey(String secretKey){
        byte[] decode = Decoders.BASE64.decode(secretKey);
        return Keys.hmacShaKeyFor(decode);
    }

    public Date getExpirationDate(String token){
        return Jwts.parser()
                .verifyWith(getSignKey(secretKey))
                .build()
                .parseSignedClaims(token)
                .getPayload()
                .getExpiration();
    }
    public String getUsername(String token){
        return Jwts.parser()
                .verifyWith(getSignKey(secretKey))
                .build()
                .parseSignedClaims(token)
                .getPayload()
                .getSubject();
    }

    public Boolean isExpired(String token){
        return getExpirationDate(token).before(new Date());
    }

    public Boolean validateToken(String token, UserDetails userDetails){
        return !isExpired(token) && userDetails.getUsername().equals(getUsername(token));
    }



}
