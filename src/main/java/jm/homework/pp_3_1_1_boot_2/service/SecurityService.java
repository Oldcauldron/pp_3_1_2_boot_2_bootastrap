package jm.homework.pp_3_1_1_boot_2.service;


import jm.homework.pp_3_1_1_boot_2.model.User;
import org.springframework.security.core.Authentication;

public interface SecurityService {
    void autoLogin(User user);
//    void autoLogin(String username, String password);
    boolean preauthorizeFunc(int id, Authentication authentication);
}
