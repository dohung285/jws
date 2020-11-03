package com.example.jwtsignaturedemo;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

import java.security.interfaces.RSAPublicKey;
import java.text.ParseException;
import java.util.Date;

@SpringBootApplication
public class JwtSignatureDemoApplication {

	public static void main(String[] args) {
		SpringApplication.run(JwtSignatureDemoApplication.class, args);

		// jsonWebSignatureWithRSA();

		// createAndVerifyJWS();

		// JWS can also secure JSON Web Tokens
		jwsSecureJWT();

	}

	private static void jwsSecureJWT() {
		// RSA signatures require a public and private RSA key pair, the public key
		// must be made known to the JWS recipient in order to verify the signatures
		RSAKey rsaJWK;
		try {
			rsaJWK = new RSAKeyGenerator(2048).keyID("123").generate();
			RSAKey rsaPublicJWK = rsaJWK.toPublicJWK();

			RSAPublicKey rsaPublicJWK2 = rsaJWK.toRSAPublicKey();

			if (rsaPublicJWK.equals(rsaPublicJWK2)) {
				System.out.println("trung nhau");
			} else {
				System.out.println("Khong trung nhau");
			}

			// Create RSA-signer with the private key
			JWSSigner signer = new RSASSASigner(rsaJWK);

			// Prepare JWT with claims set
			JWTClaimsSet claimsSet = new JWTClaimsSet.Builder().subject("alice").issuer("https://c2id.com")
					.expirationTime(new Date(new Date().getTime() + 60 * 1000)).build();

			SignedJWT signedJWT = new SignedJWT(
					new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(rsaJWK.getKeyID()).build(), claimsSet);

			// Compute the RSA signature
			signedJWT.sign(signer);

			// To serialize to compact form, produces something like
			// eyJhbGciOiJSUzI1NiJ9.SW4gUlNBIHdlIHRydXN0IQ.IRMQENi4nJyp4er2L
			// mZq3ivwoAjqa1uUkSBKFIX7ATndFF5ivnt-m8uApHO4kfIFOrW7w2Ezmlg3Qd
			// maXlS9DhN0nUk_hGI3amEjkKd0BWYCB8vfUbUv0XGjQip78AI4z1PrFRNidm7
			// -jPDm5Iq0SZnjKjCNS5Q15fokXZc8u0A
			String s = signedJWT.serialize();

			// On the consumer side, parse the JWS and verify its RSA signature
			signedJWT = SignedJWT.parse(s);

			JWSVerifier verifier = new RSASSAVerifier(rsaPublicJWK);
			// assertTrue(signedJWT.verify(verifier));

			if (signedJWT.verify(verifier)) {
				System.out.println("signedJWT.verify(verifier) == TRUE");
			} else {
				System.out.println("signedJWT.verify(verifier) == FALSE");
			}
		} catch (JOSEException e1) {
			e1.printStackTrace();
		} catch (ParseException e) {
			e.printStackTrace();
		}

	}

	private static void createAndVerifyJWS() {
		// RSA signatures require a public and private RSA key pair,
		// the public key must be made known to the JWS recipient to
		// allow the signatures to be verified
		RSAKey rsaJWK;
		try {
			rsaJWK = new RSAKeyGenerator(2048).keyID("123").generate();
			RSAKey rsaPublicJWK = rsaJWK.toPublicJWK();

			// Create RSA-signer with the private key
			JWSSigner signer = new RSASSASigner(rsaJWK);
			System.out.println("SIGNER: " + signer.toString());

			// Prepare JWS object with simple string as payload
			JWSObject jwsObject = new JWSObject(
					new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(rsaJWK.getKeyID()).build(),
					new Payload("I Love You"));

			// Compute the RSA signature
			jwsObject.sign(signer);

			// To serialize to compact form, produces something like
			// eyJhbGciOiJSUzI1NiJ9.SW4gUlNBIHdlIHRydXN0IQ.IRMQENi4nJyp4er2L
			// mZq3ivwoAjqa1uUkSBKFIX7ATndFF5ivnt-m8uApHO4kfIFOrW7w2Ezmlg3Qd
			// maXlS9DhN0nUk_hGI3amEjkKd0BWYCB8vfUbUv0XGjQip78AI4z1PrFRNidm7
			// -jPDm5Iq0SZnjKjCNS5Q15fokXZc8u0A
			String s = jwsObject.serialize();

			// To parse the JWS and verify it, e.g. on client-side
			jwsObject = JWSObject.parse(s);

			JWSVerifier verifier = new RSASSAVerifier(rsaPublicJWK);
			if (jwsObject.verify(verifier)) {
				System.out.println(" jwsObject.verify(verifier) == TRUE ");
			} else {
				System.out.println(" jwsObject.verify(verifier) == FALSE ");
			}

			if (jwsObject.getPayload().toString().equals("I Love You")) {
				System.out.println(" jwsObject.getPayload().toString().equals(\"I Love You\") == TRUE ");
			} else {
				System.out.println(" jwsObject.getPayload().toString().equals(\"I Love You\") == FALSE ");
			}

		} catch (JOSEException e) {
			e.printStackTrace();
		} catch (ParseException e) {
			e.printStackTrace();
		}

//		assertTrue(jwsObject.verify(verifier));
//
//		assertEquals("In RSA we trust!", jwsObject.getPayload().toString());

	}

	private static void jsonWebSignatureWithRSA() {
		// RSA signatures require a public and private RSA key pair,
		// the public key must be made known to the JWS recipient to allow the
		// signatures to be verified
		RSAKey rsaJWK = null;
		try {
			rsaJWK = new RSAKeyGenerator(2048).keyID("123").generate();
			RSAKey rsaPublicJWK = rsaJWK.toPublicJWK();

			// Create RSA-signer with the private key
			JWSSigner signer = new RSASSASigner(rsaJWK);

			// Prepare JWS object with simple string as payload
			JWSObject jwsObject = new JWSObject(
					new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(rsaJWK.getKeyID()).build(),
					new Payload("In RSA we trust!"));

			// Compute the RSA signature
			jwsObject.sign(signer);

			// To serialize to compact form, produces something like
			// eyJhbGciOiJSUzI1NiJ9.SW4gUlNBIHdlIHRydXN0IQ.IRMQENi4nJyp4er2L
			// mZq3ivwoAjqa1uUkSBKFIX7ATndFF5ivnt-m8uApHO4kfIFOrW7w2Ezmlg3Qd
			// maXlS9DhN0nUk_hGI3amEjkKd0BWYCB8vfUbUv0XGjQip78AI4z1PrFRNidm7
			// -jPDm5Iq0SZnjKjCNS5Q15fokXZc8u0A
			String s = jwsObject.serialize();

// To parse the JWS and verify it, e.g. on client-side
			jwsObject = JWSObject.parse(s);

			JWSVerifier verifier = new RSASSAVerifier(rsaPublicJWK);

			if (jwsObject.verify(verifier)) {
				System.out.println("jwsObject.verify(verifier)==true");
			} else {
				System.out.println("jwsObject.verify(verifier)== false");
			}

			if (jwsObject.getPayload().toString().equals("In RSA we trust!")) {
				System.out.println("jwsObject.getPayload().toString().equals(\"In RSA we trust!\") == true");
			} else {
				System.out.println("jwsObject.getPayload().toString().equals(\"In RSA we trust!\") == false");
			}

		} catch (JOSEException e) {
			e.printStackTrace();
		} catch (ParseException e) {
			e.printStackTrace();
		}

	}

}
