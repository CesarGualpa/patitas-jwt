package com.krakedev.jwt.controllers;

import java.util.Map;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.auth0.jwt.interfaces.DecodedJWT;
import com.krakedev.jwt.entidades.Usuario;
import com.krakedev.jwt.services.UsuarioService;
import com.krakedev.jwt.utils.JwtUtil;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

    private final UsuarioService usuarioService;
    private final JwtUtil jwtUtil;

    public AuthController(
            UsuarioService usuarioService,
            JwtUtil jwtUtil) {

        this.usuarioService = usuarioService;
        this.jwtUtil = jwtUtil;
    }

    @PostMapping("/registrar")
    public ResponseEntity<?> registrar(@RequestBody Usuario usuario) {

        try {

            Usuario usuarioNuevo = usuarioService.guardar(usuario);

            return ResponseEntity.status(HttpStatus.CREATED)
                    .body(Map.of(
                            "id", usuarioNuevo.getId(),
                            "username", usuarioNuevo.getUsername(),
                            "rol", usuarioNuevo.getRol()));

        } catch (Exception e) {

            return ResponseEntity.status(
                    HttpStatus.INTERNAL_SERVER_ERROR)
                    .body("Error al registrar usuario: "
                            + e.getMessage());
        }
    }

    @PostMapping("/login")
    public ResponseEntity<?> login(
            @RequestBody Map<String, String> credenciales) {

        try {

            String username = credenciales.get("username");
            String password = credenciales.get("password");

            if (username == null || password == null) {

                return ResponseEntity.badRequest()
                        .body("Debe indicar username y password");
            }

            boolean autenticado =
                    usuarioService.autenticar(username, password);

            if (!autenticado) {

                return ResponseEntity
                        .status(HttpStatus.UNAUTHORIZED)
                        .body("Usuario o contraseña incorrecta");
            }

            Usuario usuario =
                    usuarioService.buscarPorUsername(username);

            String token = jwtUtil.generarToken(
                    usuario.getUsername(),
                    usuario.getRol());

            return ResponseEntity.ok(
                    Map.of("token", token));

        } catch (Exception e) {

            return ResponseEntity
                    .status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body("Error durante el login: "
                            + e.getMessage());
        }
    }

    @GetMapping("/perfil")
    public ResponseEntity<?> verPerfil(
            @RequestHeader(
                    value = "Authorization",
                    required = false)
            String authHeader) {

        if (authHeader == null
                || !authHeader.startsWith("Bearer ")) {

            return ResponseEntity
                    .status(HttpStatus.UNAUTHORIZED)
                    .body(
                        "Acceso denegado: debes proporcionar "
                        + "un token Bearer valido en la "
                        + "cabecera Authorization");
        }

        String token = authHeader.substring(7);

        DecodedJWT datosToken =
                jwtUtil.validarToken(token);

        if (datosToken == null) {

            return ResponseEntity
                    .status(HttpStatus.UNAUTHORIZED)
                    .body(
                        "Acceso denegado: token invalido "
                        + "o expirado");
        }

        String username = datosToken.getSubject();

        String rol = datosToken
                .getClaim("rol")
                .asString();

        String mensaje;

        if ("ADMIN".equalsIgnoreCase(rol)) {

            mensaje =
                    "Bienvenido voluntario del refugio. "
                    + "Puedes gestionar rescates y adopciones.";

        } else {

            mensaje =
                    "Bienvenido adoptante registrado. "
                    + "Puedes consultar mascotas disponibles.";
        }

        return ResponseEntity.ok(
                Map.of(
                        "estatus",
                        "Autenticado exitosamente",
                        "usuario",
                        username,
                        "rol",
                        rol,
                        "mensaje",
                        mensaje));
    }
}