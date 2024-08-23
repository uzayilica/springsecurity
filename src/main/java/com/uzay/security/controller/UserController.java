package com.uzay.security.controller;

import com.uzay.security.SecurityApplication;
import com.uzay.security.jwt.JwtService;
import com.uzay.security.modal.Roles;
import com.uzay.security.modal.User;
import com.uzay.security.repository.UserRepository;
import com.uzay.security.service.MyUserDetailsService;
import org.springframework.http.HttpStatus;
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
    public ResponseEntity<?> login(@RequestBody User user) {
        try {
            // Kullanıcıyı bulma
            UserDetails userDetails = myUserDetailsService.loadUserByUsername(user.getUsername());

            // Şifre doğrulama
            if (passwordEncoder.matches(user.getPassword(), userDetails.getPassword())) {
                // Giriş başarılı, token oluşturma
                UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken =
                        new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
                SecurityContextHolder.getContext().setAuthentication(usernamePasswordAuthenticationToken);

                // Token oluşturma
                String token = jwtService.generateToken(userDetails);

                return ResponseEntity.ok(token);
            } else {
                // Şifre hatalı
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Şifre hatalı");
            }
        } catch (UsernameNotFoundException e) {
            // Kullanıcı bulunamadı
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Kullanıcı bulunamadı");
        } catch (Exception e) {
            // Bilinmeyen hata
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("Bilinmeyen bir hata oluştu");
        }
    }





}
