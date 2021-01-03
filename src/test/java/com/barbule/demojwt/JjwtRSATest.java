package com.barbule.demojwt;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;

import java.io.File;
import java.io.IOException;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import java.util.Date;
import java.util.UUID;

public class JjwtRSATest {

    public static void main(String[] a) throws InvalidKeySpecException, NoSuchAlgorithmException, IOException {

//        Generate Private and Public RSA Key
//        Generate an RSA private key, of size 2048, and output it to a file named key.pem:
//        $ openssl genrsa 2048 | openssl pkcs8 -topk8 -nocrypt -out private.pem

//        Extract the public key from the key pair, which can be used in a certificate:
//        $ openssl rsa -in private.pem -outform PEM -pubout -out public.pem

        String jwt = createJwtSignedHMAC();
        System.out.println("-------- createJwtSignedHMAC -------- ");
        System.out.println("JWT => " + jwt);

        Jws<Claims> claimsJws = parseJwt(jwt);
        System.out.println("--------  parseJwt -------- ");
        System.out.println("claimsJws => " + claimsJws);

    }

    public static String createJwtSignedHMAC() throws InvalidKeySpecException, NoSuchAlgorithmException, IOException {

        PrivateKey privateKey = getPrivateKey();

        Instant now = Instant.now();
        String jwtToken = Jwts.builder()
                .claim("name", "Jane Doe")
                .claim("email", "jane@example.com")
                .setSubject("jane")
                .setId(UUID.randomUUID().toString())
                .setIssuedAt(Date.from(now))
                .setExpiration(Date.from(now.plus(5l, ChronoUnit.MINUTES)))
                .signWith(privateKey)
                .compact();

        return jwtToken;
    }

    private static PrivateKey getPrivateKey() throws NoSuchAlgorithmException, InvalidKeySpecException, IOException {
        File file = new File("private.pem");
        String rsaPrivateKey = Files.readString(file.toPath(), Charset.defaultCharset());

        rsaPrivateKey = rsaPrivateKey.replace("-----BEGIN PRIVATE KEY-----", "");
        rsaPrivateKey = rsaPrivateKey.replace("-----END PRIVATE KEY-----", "");
        rsaPrivateKey = rsaPrivateKey.replace("\n", "");


//        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(Base64.getDecoder().decode(rsaPrivateKey));
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(Base64.getDecoder().decode(rsaPrivateKey));
        KeyFactory kf = KeyFactory.getInstance("RSA");
        PrivateKey privKey = kf.generatePrivate(keySpec);
        return privKey;
    }

    public static Jws<Claims> parseJwt(String jwtString) throws InvalidKeySpecException, NoSuchAlgorithmException, IOException {

        PublicKey publicKey = getPublicKey();

        Jws<Claims> jwt = Jwts.parserBuilder()
                .setSigningKey(publicKey)
                .build()
                .parseClaimsJws(jwtString);

        return jwt;
    }

    private static PublicKey getPublicKey() throws NoSuchAlgorithmException, InvalidKeySpecException, IOException {
        File file = new File("public.pem");
        String rsaPublicKey = Files.readString(file.toPath(), Charset.defaultCharset());

        rsaPublicKey = rsaPublicKey.replace("-----BEGIN PUBLIC KEY-----", "");
        rsaPublicKey = rsaPublicKey.replace("-----END PUBLIC KEY-----", "");
        rsaPublicKey = rsaPublicKey.replace("\n", "");

        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(Base64.getDecoder().decode(rsaPublicKey));
        KeyFactory kf = KeyFactory.getInstance("RSA");
        PublicKey publicKey = kf.generatePublic(keySpec);
        return publicKey;
    }
}
