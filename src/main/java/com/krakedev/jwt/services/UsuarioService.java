package com.krakedev.jwt.services;

import org.springframework.stereotype.Service;

import com.krakedev.jwt.entidades.Usuario;
import com.krakedev.jwt.repositories.UsuarioRepository;

@Service
public class UsuarioService {

    private final UsuarioRepository usuarioRepository;

    public UsuarioService(UsuarioRepository usuarioRepository) {
        this.usuarioRepository = usuarioRepository;
    }

    public Usuario guardar(Usuario usuario) {

        return usuarioRepository.save(usuario);
    }

    public boolean autenticar(String username, String password) {

        return usuarioRepository.findByUsername(username)
                .map(usuario -> usuario.getPassword().equals(password))
                .orElse(false);
    }

    public Usuario buscarPorUsername(String username) {

        return usuarioRepository.findByUsername(username)
                .orElse(null);
    }
}