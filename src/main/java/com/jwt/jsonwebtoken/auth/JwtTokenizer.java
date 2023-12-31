package com.jwt.jsonwebtoken.auth;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.io.Encoders;
import io.jsonwebtoken.security.Keys;

import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.util.Calendar;
import java.util.Date;
import java.util.Map;

public class JwtTokenizer {

    //encodeBase64SecretKey() 메서드는 Plain Text 형태인 Secret Key의 byte[]를 Base64 형식의 문자열로 인코딩해줍니다.
    //jjwt가 버전업 되면서 Plain Text 자체를 Secret Key로 사용하는 것은
    // 암호학(cryptographic)적인 작업에 사용되는 Key가 항상 바이너리(byte array)라는 사실과 맞지 않는 것을 감안하여
    // Plain Text 자체를 Secret Key로 사용하는 것을 권장하지 않고 있습니다.
    //
    public String encodeBase64SecretKey(String secretKey){
        return Encoders.BASE64.encode(secretKey.getBytes(StandardCharsets.UTF_8));
    }

    public String generateAccessToken(Map<String, Object> claims,
                                      String subject,
                                      Date expiration,
                                      String base64EncodedSecretKey) {

        Key key = getKeyFromBase64EncodedKey(base64EncodedSecretKey);
        return Jwts.builder()
                .setClaims(claims)
                .setSubject(subject)
                .setIssuedAt(Calendar.getInstance().getTime())
                .setExpiration(expiration)
                .signWith(key)
                .compact();
    }

    public String generateRefreshToken(String subject,
                                       Date expiration,
                                       String base64EncodedSecretKey){
        Key key = getKeyFromBase64EncodedKey(base64EncodedSecretKey);
        return Jwts.builder()
                .setSubject(subject)
                .setIssuedAt(Calendar.getInstance().getTime())
                .setExpiration(expiration)
                .signWith(key)
                .compact();
    }


    //JWT의 서명에 사용할 Secret Key를 생성
    //적절한 HMAC 알고리즘을 적용한 Key(java.security.Key) 객체를 생성합니다.
    private Key getKeyFromBase64EncodedKey(String base64EncodedSecretKey) {
        byte[] keyBytes = Decoders.BASE64.decode(base64EncodedSecretKey);
        Key key = Keys.hmacShaKeyFor(keyBytes);
        return key;
    }



    //JWT 검증을 위한 메소드
    //Signature를 검증함으로써 JWT 위/변조 여부를 확인
    //jjwt에서는 JWT를 생성할 때 서명에 사용된 Secret Key를 이용해 내부적으로 Signature를 검증한 후,
    //검증에 성공하면 JWT를 파싱 해서 Claims를 얻을 수 있습니다.
    //signature를 검증하는 용도이므로 Claims를 리턴할 필요는 없습니다.
    public void verifySignature(String jws,String base64EncodedSecretKey){
        Key key = getKeyFromBase64EncodedKey(base64EncodedSecretKey);

        Jwts.parserBuilder()
                .setSigningKey(key)
                .build()
                .parseClaimsJws(jws);
    }
}
