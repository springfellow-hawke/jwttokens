package za.co.sfh.jwt;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.jwk.source.RemoteJWKSet;
import com.nimbusds.jose.proc.JWSKeySelector;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.proc.BadJWTException;
import com.nimbusds.jwt.proc.ConfigurableJWTProcessor;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;

import java.io.IOException;
import java.net.URL;
import java.util.Base64;
import java.util.Objects;


public class TestExtractJWT {

    private static final String JWK_URl_SUFFIX = "/.well-known/jwks.json";
    private static final int PAYLOAD = 1;
    private static final int JWT_PARTS = 3;
    private static final String ISS = "iss";

    public static void main(String[] args) {
        TestExtractJWT jwt = new TestExtractJWT();
        jwt.extractInfo();
        ;
    }

    private void extractInfo() {

        try {


            String token = getToken();
            String jsonWebKeyFileURL = getJsonWebKeyURL(token);

            ConfigurableJWTProcessor jwtProcessor = new DefaultJWTProcessor();

            JWKSource jwkSource = new RemoteJWKSet(new URL(jsonWebKeyFileURL));

            JWSAlgorithm jwsAlgorithm = JWSAlgorithm.RS256;

            JWSKeySelector keySelector = new JWSVerificationKeySelector(jwsAlgorithm, jwkSource);

            // keySelector => RS256
            jwtProcessor.setJWSKeySelector(keySelector);

            JWTClaimsSet claimsSet = jwtProcessor.process(getToken(), null);

            Object roles = claimsSet.getClaims().get("scope");

            System.out.println("Roles defined in token: " + roles.toString());

        } catch (BadJWTException e) {
            e.printStackTrace();
        } catch (java.text.ParseException ex) {
            ex.printStackTrace();
        } catch (Exception ex) {
            ex.printStackTrace();
        }
    }

    protected String getJsonWebKeyURL(String token) throws Exception {

        JsonNode payload = getPayload(token);
        JsonNode issJsonElement = getPayload(token).get(ISS);
        if (Objects.isNull(issJsonElement)) {
            System.out.println("ERRRR");
        }
        return issJsonElement.asText() + JWK_URl_SUFFIX;
    }

    protected JsonNode getPayload(String jwt) throws Exception {
        try {
            ObjectMapper objectMapper = new ObjectMapper();

            validateJWT(jwt);
            final String payload = jwt.split("\\.")[PAYLOAD];
            final byte[] payloadBytes = Base64.getUrlDecoder().decode(payload);
            final String payloadString = new String(payloadBytes, "UTF-8");
            return objectMapper.readTree(payloadString);
        } catch (IOException e) {
            e.printStackTrace();
        }
        return null;
    }

    protected void validateJWT(String jwt) throws Exception {
        // Basic validation to check if token has three parts.
        final String[] jwtParts = jwt.split("\\.");
        if (jwtParts.length != JWT_PARTS) {
            throw new Exception("Invalid token");
        }
    }

    private String getToken() {
        String token = "eyJraWQiOiJXVDRUT1JQQ0JqdlJWUmVackl6aUhWSmxjXC84ZnNLc2N2OVd6c0V5UzZydz0iLCJhbGciOiJSUzI1NiJ9.eyJzdWIiOiIxZzRja3AzNm0zdWx1YTJhMW1sYXI4bG42biIsInRva2VuX3VzZSI6ImFjY2VzcyIsInNjb3BlIjoiUk9MRVNcL01BTUEiLCJhdXRoX3RpbWUiOjE1ODYxODk1ODgsImlzcyI6Imh0dHBzOlwvXC9jb2duaXRvLWlkcC5ldS13ZXN0LTEuYW1hem9uYXdzLmNvbVwvZXUtd2VzdC0xX2FHekgwcWJ1QyIsImV4cCI6MTU4NjE5MzE4OCwiaWF0IjoxNTg2MTg5NTg4LCJ2ZXJzaW9uIjoyLCJqdGkiOiJhNTM4NjRjNS01ZmViLTQ1NGEtYTBlYy1lNmYyZjAxM2ZmMTUiLCJjbGllbnRfaWQiOiIxZzRja3AzNm0zdWx1YTJhMW1sYXI4bG42biJ9.gRdyi6ghyBKLxr8GUZ7ZyCccF2CZTM8u8uX3FanfnC1c1Ehw7wd1-XIfsNM1t2Qqs-OfGLK610MgYozvEDSN4LrN1zsPIIzM4Qr4X4pdwh5L0cGSF0zI3ikddrUuhYgxv6wiqIEiP8E-HsKO9x4m8xGWgDQXxZLR7CCINtgq8U5IsvkHkyAyjInc1EmUNtsYRx7gfY8zCXRl4i4ygCCOBIrF6OWLT9ZAQRDBdKDbHVhBzLifJcMBjLp0Bw5U63Esf_cgGypNLddYybD_nVYUiaDfAH1vSJbISn54lzyhPzc0AEoccwWyqdonWztqg4xb_g3yMybsFX2cvPpQlL103A";
        return token;
    }
}

