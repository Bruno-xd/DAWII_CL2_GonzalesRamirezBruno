package pe.edu.cibertec.appwebventascibertec.controller.frontoffice;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import lombok.AllArgsConstructor;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;
import pe.edu.cibertec.appwebventascibertec.model.bd.Usuario;
import pe.edu.cibertec.appwebventascibertec.service.UsuarioService;
@AllArgsConstructor
@Controller
@RequestMapping("/auth")
public class LoginController {

    private UsuarioService usuarioService;

    @GetMapping("/login")
    public String login(){
        return "frontoffice/auth/frmLogin";
    }

    @GetMapping("/registrar")
    public String registrar(){
        return "frontoffice/auth/frmRegistroUsuario";
    }

    @PostMapping("/login-success")
    public String loginSucces(HttpServletRequest request){
        UserDetails usuario = (UserDetails) SecurityContextHolder
                .getContext()
                .getAuthentication()
                .getPrincipal();
        HttpSession session = request.getSession();
        session.setAttribute("usuario", usuario.getUsername());
        return "frontoffice/auth/home";
    }

    @PostMapping("/guardarUsuario")
    public String guardarUsuario(@ModelAttribute Usuario usuario){
        usuarioService.saveUser(usuario);
        return "frontoffice/auth/frmLogin";
    }

    @GetMapping("/cambiar-password")
    public String cambiarPasswordForm(@RequestParam String passwordActual,
                                      @RequestParam String nuevaPassword,
                                      HttpServletRequest request) {
        String usuario = (String) request.getSession().getAttribute("usuario");

        if (usuarioService.verificarPassword(usuario, passwordActual)) {
            usuarioService.cambiarPassword(usuario, nuevaPassword);
            return "redirect:/home";
        } else {
            return "frontoffice/auth/frmCambioPassword";
        }
    }

    @PostMapping("/cambiar-password")
    public String cambiarPassword(@RequestParam String newPassword, HttpServletRequest request) {
        String usuario = (String) request.getSession().getAttribute("usuario");
        if (newPassword != null && !newPassword.isEmpty()) {
            usuarioService.cambiarPassword(usuario, newPassword);
            return "frontoffice/auth/frmCambioPassword";
        } else {
            return "frontoffice/auth/frmCambioPassword";
        }
    }

    @GetMapping("/cerrar-sesion")
    public String cerrarSesion(HttpServletRequest request) {
        HttpSession session = request.getSession();
        session.invalidate();
        SecurityContextHolder.clearContext();
        return "frontoffice/auth/frmLogin";
    }
}
