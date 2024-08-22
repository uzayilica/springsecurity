package com.uzay.security.controller;

import com.uzay.security.SecurityApplication;
import com.uzay.security.jwt.JwtService;
import com.uzay.security.modal.Roles;
import com.uzay.security.modal.User;
import com.uzay.security.repository.UserRepository;
import com.uzay.security.service.MyUserDetailsService;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

@RequestMapping("/auth")
@RestController
public class UserController {

    private final MyUserDetailsService myUserDetailsService;
    private final PasswordEncoder passwordEncoder;
    private final UserRepository userRepository;
    private final JwtService jwtService;

    public UserController(MyUserDetailsService myUserDetailsService, PasswordEncoder passwordEncoder, UserRepository userRepository, JwtService jwtService) {
        this.myUserDetailsService = myUserDetailsService;
        this.passwordEncoder = passwordEncoder;
        this.userRepository = userRepository;
        this.jwtService = jwtService;
    }

    @PostMapping("/register")
    public ResponseEntity<?> Register(@RequestBody User user) {
        //varsa boşuna eklemeyelim
        try {
            UserDetails userDetails = myUserDetailsService.loadUserByUsername(user.getUsername());
            return ResponseEntity.ok().body("user zaten var lütfen login olun");
        }
       catch (UsernameNotFoundException e) {
            User usernew =new User();
            usernew.setUsername(user.getUsername());
            usernew.setPassword(passwordEncoder.encode(user.getPassword()));
            usernew.setRole(Roles.ROLE_USER);
            userRepository.save(usernew);
            return ResponseEntity.ok().body("user eklendi");



       }
        catch (Exception e) {
            return ResponseEntity.ok().body("bilinmeyen bir hata oluştu");
        }

    }



    @PostMapping("/login")
    public ResponseEntity<?>Login(@RequestBody User user){
        try {
            //önce kullanıcı adı var mı diye bakalım varsa şifreye bakalım
            UserDetails userDetails = myUserDetailsService.loadUserByUsername(user.getUsername());

            //tamam var şimdi şifreye bakalım

            if(passwordEncoder.matches(user.getPassword(),userDetails.getPassword())){
                //giriş başarılı
                //token oluştur contexte ekle
                UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken = new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
                SecurityContextHolder.getContext().setAuthentication(usernamePasswordAuthenticationToken);

                // tokeni üretelim
                String token = jwtService.generateToken(userDetails);

                return ResponseEntity.ok().body(token);
            }
            else {
                return ResponseEntity.ok().body("şifre hatalı");
            }
        }

catch (UsernameNotFoundException e) {
            return ResponseEntity.ok().body("kullanıcı bulunumadı");
}
        catch (Exception e) {

            return ResponseEntity.ok().body("bilinmeyen bir hata olun");
        }

    }




}
