package com.krakedev.jwt.utils;

import java.util.Date;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.auth0.jwt.interfaces.JWTVerifier;

@Component
public class JwtUtil {

    private static final Logger logger =
            LoggerFactory.getLogger(JwtUtil.class);

    private static final String EMISOR = "PatitasAlRescate";

    private final Algorithm algoritmo;
    private final long tiempoExpiracion;

    public JwtUtil(
            @Value("${jwt.secret}") String claveSecreta,
            @Value("${jwt.expiration-ms}") long tiempoExpiracion) {

        this.algoritmo = Algorithm.HMAC256(claveSecreta);
        this.tiempoExpiracion = tiempoExpiracion;
    }

    public String generarToken(String username, String rol) {

        long tiempoActual = System.currentTimeMillis();

        Date fechaEmision = new Date(tiempoActual);

        Date fechaExpiracion =
                new Date(tiempoActual + tiempoExpiracion);

        return JWT.create()
                .withIssuer(EMISOR)
                .withSubject(username)
                .withIssuedAt(fechaEmision)
                .withExpiresAt(fechaExpiracion)
                .withClaim("rol", rol)
                .sign(algoritmo);
    }

    public DecodedJWT validarToken(String token) {

        try {

            JWTVerifier verificador = JWT.require(algoritmo)
                    .withIssuer(EMISOR)
                    .build();

            return verificador.verify(token);

        } catch (Exception e) {

            logger.error(
                    "Error al validar token JWT: {}",
                    e.getMessage());

            return null;
        }
    }
}