package com.jwt.jsonwebtoken.auth;

import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;

import java.util.*;
import java.util.concurrent.TimeUnit;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.notNullValue;
import static org.junit.jupiter.api.Assertions.*;

@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class JwtTokenizerTest {

    private static JwtTokenizer jwtTokenizer;
    private String secretKey;
    private String base64EncodedSecretKey;


    @BeforeAll
    public void init(){
        jwtTokenizer = new JwtTokenizer();
        secretKey="kevin1234123412341234123412341234";
        base64EncodedSecretKey =jwtTokenizer.encodeBase64SecretKey(secretKey);
        //a2V2aW4xMjM0MTIzNDEyMzQxMjM0MTIzNDEyMzQxMjM0
    }

    @Test
    public void encodeBase64SecretKeyTest(){
        System.out.println("base64EncodedSecretKey = " + base64EncodedSecretKey);
        assertThat(secretKey,is(new String(Decoders.BASE64.decode(base64EncodedSecretKey))));
    }

    @Test
    public void generateAccessTokenTest() {
        Map<String, Object> claims = new HashMap<>();
        claims.put("memberId", 1);
        claims.put("roles", List.of("USER"));

        String subject = "test access token";
        Calendar calendar = Calendar.getInstance();
        calendar.add(Calendar.MINUTE, 10);
        Date expiration = calendar.getTime();
        String accessToken = jwtTokenizer.generateAccessToken(claims, subject, expiration, base64EncodedSecretKey);

        System.out.println("accessToken = " + accessToken);
        assertThat(accessToken,notNullValue());
    }


    @Test
    public void generateRefreshTokenTest() {
        String subject = "test refresh token";
        Calendar calendar = Calendar.getInstance();
        calendar.add(Calendar.HOUR, 24);
        Date expiration = calendar.getTime();

        String refreshToken = jwtTokenizer.generateRefreshToken(subject, expiration, base64EncodedSecretKey);

        System.out.println(refreshToken);

        assertThat(refreshToken, notNullValue());
    }



    @DisplayName("jws를 검증할때 예외를 던지지 않는다")
    @Test
    public void verifySignatureTest(){
        String accessToken = getAccessToken(Calendar.MINUTE, 10);
        assertDoesNotThrow(()->jwtTokenizer.verifySignature(accessToken,base64EncodedSecretKey));
    }

    @DisplayName("jws 검증시 만료된 jwt예외를 던진다")
    @Test
    public void verifyExpirationTest() throws InterruptedException{
        String accessToken = getAccessToken(Calendar.SECOND, 1);

        assertDoesNotThrow(()->jwtTokenizer.verifySignature(accessToken,base64EncodedSecretKey));

        TimeUnit.MILLISECONDS.sleep(1500);

        assertThrows(ExpiredJwtException.class, () -> jwtTokenizer.verifySignature(accessToken, base64EncodedSecretKey));
    }


    private String getAccessToken(int timeUnit, int timeAmount){
        Map<String,Object> claims =new HashMap<>();
        claims.put("memberId",1);
        claims.put("roles",List.of("USER"));

        String subject="test access token";
        Calendar calendar=Calendar.getInstance();
        calendar.add(timeUnit,timeAmount);
        Date expiration = calendar.getTime();
        String accessToken = jwtTokenizer.generateAccessToken(claims, subject, expiration, base64EncodedSecretKey);

        return accessToken;
    }
}