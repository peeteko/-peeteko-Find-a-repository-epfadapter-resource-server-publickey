package be.post.epfadapter.controller;

import io.jsonwebtoken.Jwt;
import org.junit.Assert;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class JwtTokenGenerationAndVerificationTest {
    private static final Logger LOGGER = LoggerFactory.getLogger(JwtTokenGenerationAndVerificationTest.class);


    @Test
    void generateJWTToken() throws Exception{
        String jwtString = JwtTestHelper.getJwtTokenSignedWithPrivateKey();
        LOGGER.info("jwt string to be added in Authorization Bearer " + jwtString);
        assertViaPublicKey(jwtString);
    }

    private void assertViaPublicKey(String jwtString) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        Jwt jwt = JwtTestHelper.parseJwtWithPublicKeyVerification(jwtString);
        Assert.assertTrue(jwt.getBody().toString().contains("scope=connections:read connections:write"));
    }

}
