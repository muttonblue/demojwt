package com.barbule.demojwt;

import com.barbule.demojwt.model.UserLogin;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.io.Encoders;
import io.jsonwebtoken.security.Keys;
import org.apache.commons.lang3.StringUtils;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.*;

public class JjwtHS256Test {

    private static final SignatureAlgorithm algorithm = SignatureAlgorithm.HS256; //or HS384 or HS512
    private static final String algorithmJscName = algorithm.getJcaName();

    public static void main(String[] a) {
        /* create secret key */
//        java.security.Key key = Keys.secretKeyFor(SignatureAlgorithm.HS256);
        SecretKey key = Keys.secretKeyFor(algorithm); //or HS384 or HS512

        String secretString = Encoders.BASE64.encode(key.getEncoded());
//        String secretString2 = Encoders.BASE64.encode("thailife2020".getBytes(StandardCharsets.UTF_8));

        System.out.println("secret => " + secretString);

        String jwtt = createJWT(key);
        System.out.println("createJWT => " + jwtt);

        UserLogin userLogin = new UserLogin("John", "Rambo");
        Map<String, Object> claims = new HashMap<>();

        claims.put("userLogin", userLogin);

        String jwt = Jwts.builder()
                .addClaims(claims)
                .setSubject("Joe")
                .signWith(key)
                .compact();

        System.out.printf("\n%s - %s", key.getAlgorithm(), jwt);

        Jws<Claims> jws = parseJwt(jwt, secretString);
        Jws<Claims> jwst = parseJwt(jwtt, secretString);
        System.out.println(" 1 --- " + jws);
        System.out.println(" 2 --- " + jwst);
    }

    public static String createJWT(SecretKey key) {

        Instant now = Instant.now();
        String jwtToken = Jwts.builder()
                .claim("name", "Jane Doe")
                .claim("email", "jane@example.com")
                .setSubject("Joe")
                .setId(UUID.randomUUID().toString())
                .setIssuedAt(Date.from(now))
                .setExpiration(Date.from(now.plus(5l, ChronoUnit.MINUTES)))
                .signWith(key)
                .compact();

        return jwtToken;
    }

    public static Jws<Claims> parseJwt(String jwtString, String secret) {
        Key hmacKey = getKey(secret);

        return Jwts.parserBuilder()
                .setSigningKey(hmacKey)
                .build()
                .parseClaimsJws(jwtString);
    }

    public static Key getKey(String secret) {
        return new SecretKeySpec(Base64.getDecoder().decode(secret), algorithmJscName);
    }
}
