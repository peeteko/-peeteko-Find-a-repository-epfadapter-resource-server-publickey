package be.post.epfadapter.controller;

import io.jsonwebtoken.Jwt;
import io.jsonwebtoken.JwtParser;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.IOException;
import java.net.URL;
import java.nio.file.Files;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.EncodedKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.time.Instant;
import java.util.Base64;
import java.util.Date;

public class JwtTestHelper {
    private static final Logger LOGGER = LoggerFactory.getLogger(JwtTestHelper.class);
    public static String getJwtTokenSignedWithPrivateKey() throws Exception {

        Instant instant = Instant.now();
        String privateKeyString = getResourceContentAsString("/certificates/pkcs8-private.key");
        PrivateKey privateKey = getPrivateKey(privateKeyString);
        return Jwts.builder().setIssuer("https://ssociam-np.bpost.cloud")
                .setSubject("users/1300819380")
                .setExpiration(Date.from(instant.plusSeconds(3600)))
                .claim("scope", "connections:read connections:write")
                .claim("client_id_name", "sml_web_ciam_np")
                .claim("Email", "bpostbelgiumtest+02@gmail.com" )
                .signWith(privateKey, SignatureAlgorithm.RS256)
                .compact();
    }

    public static Jwt parseJwtWithPublicKeyVerification(String jwtString) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        String publicKeyAsString = getResourceContentAsString("/certificates/publickey.crt");
        PublicKey publicKey = getPublicKey(publicKeyAsString);
        JwtParser jwtParser = Jwts.parserBuilder().setSigningKey(publicKey).build();

        Jwt jwt = jwtParser.parse(jwtString);
        LOGGER.info("jwt could be parsed with publicKey " + jwt.getBody());
        return jwt;
    }

    private static PrivateKey getPrivateKey(String privateKeyString) throws NoSuchAlgorithmException, InvalidKeySpecException {
        String privateKeyFormatted =  privateKeyString
                .replace("-----BEGIN PRIVATE KEY-----","")
                .replaceAll("\n", "")
                .replaceAll("\r","")
                .replace("-----END PRIVATE KEY-----", "");
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(Base64.getDecoder().decode(privateKeyFormatted.getBytes()));
        return keyFactory.generatePrivate(privateKeySpec);
    }

    private static PublicKey getPublicKey(String publicKeyString) throws NoSuchAlgorithmException, InvalidKeySpecException {
        String publicKeyFormatted =  publicKeyString
                .replace("-----BEGIN PUBLIC KEY-----","")
                .replaceAll("\n", "")
                .replaceAll("\r","")
                .replace("-----END PUBLIC KEY-----", "");
        EncodedKeySpec keySpec = new X509EncodedKeySpec(Base64.getDecoder().decode(publicKeyFormatted.getBytes()));
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePublic(keySpec);
    }



    private static String getResourceContentAsString(String resourceName) throws IOException {
        URL url = JwtTestHelper.class.getResource(resourceName);
        File file = new File(url.getFile());
        return Files.readString(file.toPath());
    }
}
