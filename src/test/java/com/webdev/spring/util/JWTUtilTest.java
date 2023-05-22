package com.webdev.spring.util;

import lombok.extern.log4j.Log4j2;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import java.util.Map;

@SpringBootTest
@Log4j2
public class JWTUtilTest {

    @Autowired
    private JWTUtil jwtUtil;

    @Test
    public void testGenerate() {
        Map<String, Object> claimMap = Map.of("mid", "ABCDE");

        String jwt = jwtUtil.generateToken(claimMap, 1);

        log.info(jwt);
    }

    @Test
    public void testValidate() {

        // 유효 시간이 지난 토큰
        String jwt = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJleHAiOjE2ODQ3NDE5MTksIm1pZCI6IkFCQ0RFIiwiaWF0IjoxNjg0NzQxODU5fQ.8crBFoJYomgkNXh-zmrORdFxkRWuZL8WwBCn_9ePWgo";

        Map<String, Object> claim = jwtUtil.validateToken(jwt);

        log.info(claim);
    }

    @Test
    public void testAll() {

        String jwt = jwtUtil.generateToken(Map.of("mid", "AAAA", "email", "aaa@bbb.com"), 1);

        log.info(jwt);

        Map<String, Object> claim = jwtUtil.validateToken(jwt);

        log.info("MID: " + claim.get("mid"));
        log.info("Email: " + claim.get("email"));
    }
}
