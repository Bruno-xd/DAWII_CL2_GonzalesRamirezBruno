package pe.edu.cibertec.appwebventascibertec.service;

import lombok.AllArgsConstructor;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import pe.edu.cibertec.appwebventascibertec.model.bd.Rol;
import pe.edu.cibertec.appwebventascibertec.model.bd.Usuario;
import pe.edu.cibertec.appwebventascibertec.repository.RolRepository;
import pe.edu.cibertec.appwebventascibertec.repository.UsuarioRepository;

import java.util.Arrays;
import java.util.HashSet;

@Service
@AllArgsConstructor
public class UsuarioService {

    private UsuarioRepository usuarioRepository;
    private RolRepository rolRepository;

    private BCryptPasswordEncoder bCryptPasswordEncoder=
            new BCryptPasswordEncoder();

    public Usuario findUserByEmail(String email){
        return usuarioRepository.findByEmail(email);
    }

    public Usuario findUserByUserName(String username){
        return usuarioRepository.findByNomusuario(username);
    }

    public Usuario saveUser(Usuario usuario){
        usuario.setPassword(bCryptPasswordEncoder.encode(
                usuario.getPassword()));
        usuario.setActivo(true);
        Rol usuarioRol = rolRepository.findByNomrol("ADMIN");
        usuario.setRoles(new HashSet<>(Arrays.asList(usuarioRol)));
        return usuarioRepository.save(usuario);
    }

    public boolean verificarPassword(String username, String password) {
        Usuario usuario = usuarioRepository.findByNomusuario(username);
        if (usuario != null) {
            return bCryptPasswordEncoder.matches(password, usuario.getPassword());
        }
        return false;
    }

    public void cambiarPassword(String username, String newPassword) {
        Usuario usuario = usuarioRepository.findByNomusuario(username);
        if (usuario != null) {
            String hashedPassword = bCryptPasswordEncoder.encode(newPassword);
            usuario.setPassword(hashedPassword);
            saveUser(usuario);
        }
    }
}
