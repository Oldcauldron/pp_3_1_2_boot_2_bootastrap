package jm.homework.pp_3_1_1_boot_2.controller;

import jm.homework.pp_3_1_1_boot_2.model.User;
import jm.homework.pp_3_1_1_boot_2.service.RoleService;
import jm.homework.pp_3_1_1_boot_2.service.SecurityService;
import jm.homework.pp_3_1_1_boot_2.service.UserService;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import javax.validation.Valid;

@Controller
public class HomeControllerNew {

    private final UserDetailsService userDetailsService;
    private final UserService userService;
    private final RoleService roleService;
    private final SecurityService securityService;

    @Value("${other.value}")
    String value;

    public HomeControllerNew(@Qualifier("userDetailsServiceImpl")
                                  UserDetailsService userDetailsService,
                          UserService userService,
                          RoleService roleService,
                          SecurityService securityService) {
        this.userDetailsService = userDetailsService;
        this.userService = userService;
        this.roleService = roleService;
        this.securityService = securityService;
    }

    @GetMapping(value = "/")
    public String getHomePage(Model model) {
        return "redirect:/logincustom";
    }

    @GetMapping(value = "/logincustom")
    public String getLoginPage(@RequestParam(value = "error", required = false) String error,
                               @RequestParam(value = "logout", required = false) String logout,
                               Model model) {
        model.addAttribute("error", error != null);
        model.addAttribute("logout", logout != null);
        return "logincust";
    }

    @PostMapping("/registration-b")
    public String registrationB(@ModelAttribute("user") @Valid User user,
                                BindingResult bindingResult,
                                Model model,
                                RedirectAttributes redirectAttributes) {
        String errorExist;
        if (bindingResult.hasErrors()) {
            redirectAttributes.addFlashAttribute("user", user);
            redirectAttributes.addFlashAttribute("org.springframework.validation.BindingResult.user", bindingResult);
            return "redirect:/admin-b";
        }
        if (userService.isExistingUserByEmail(user.getEmail())) {
            errorExist = "this email is already exist";
            redirectAttributes.addFlashAttribute("errorExist", errorExist);
            redirectAttributes.addFlashAttribute("user", user);
            return "redirect:/admin-b";
        }
        userService.addUser(user);
        return "redirect:/admin-b";
    }

}
