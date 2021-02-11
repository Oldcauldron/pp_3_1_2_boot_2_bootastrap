package jm.homework.pp_3_1_1_boot_2.service;

import jm.homework.pp_3_1_1_boot_2.model.Role;
import jm.homework.pp_3_1_1_boot_2.model.User;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.stereotype.Component;

@Component
public class SecurityServiceImpl implements SecurityService {

    private AuthenticationManager authenticationManager;
    private AuthenticationManagerBuilder authenticationManagerBuilder;
    private UserDetailsService userDetailsService;
    private UserService userService;

    @Autowired
    public SecurityServiceImpl(AuthenticationManager authenticationManager,
                               AuthenticationManagerBuilder authenticationManagerBuilder,
                               @Qualifier("userDetailsServiceImpl")
                               UserDetailsService userDetailsService,
                               UserService userService) {
        this.authenticationManager = authenticationManager;
        this.authenticationManagerBuilder = authenticationManagerBuilder;
        this.userDetailsService = userDetailsService;
        this.userService = userService;
    }

    public SecurityServiceImpl() {
    }

    @Override
    public void autoLogin(User user) {
        UserDetails userDetails = userDetailsService.loadUserByUsername(user.getEmail());
        Authentication authentication = new UsernamePasswordAuthenticationToken(userDetails, userDetails.getPassword(), userDetails.getAuthorities());
        SecurityContextHolder.getContext().setAuthentication(authentication);

    }

    @Override
    public boolean preauthorizeFunc(int id, Authentication authentication) {
        User user = (User)authentication.getPrincipal();
        boolean role_admin = authentication.getAuthorities().stream().anyMatch(x -> x.getAuthority().equals("ROLE_ADMIN"));
        return role_admin || user.getId() == id;
    }

    @Override
    public User getAuthUser() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        String email;
        Object principal = authentication.getPrincipal();
        if (principal instanceof UserDetails) {
            email = ((UserDetails)principal).getUsername();
        } else {
            email = principal.toString();
        }

        if (userService.isExistingUserByEmail(email)) {
            return (User) userDetailsService.loadUserByUsername(email);
        }
        return new User();
    }
}
