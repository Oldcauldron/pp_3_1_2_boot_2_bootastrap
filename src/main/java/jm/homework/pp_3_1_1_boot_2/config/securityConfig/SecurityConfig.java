package jm.homework.pp_3_1_1_boot_2.config.securityConfig;


import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.web.access.channel.ChannelProcessingFilter;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;


@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class SecurityConfig extends WebSecurityConfigurerAdapter {
    private final UserDetailsService userDetailsService;
    private final SuccessUserHandler successUserHandler;

    public SecurityConfig(@Qualifier("userDetailsServiceImpl")
                          UserDetailsService userDetailsService,
                          SuccessUserHandler successUserHandler) {
        this.userDetailsService = userDetailsService;
        this.successUserHandler = successUserHandler;
    }

    @Autowired
    public void configureGlobalSecurity(AuthenticationManagerBuilder auth) throws Exception {
        auth.userDetailsService(userDetailsService).passwordEncoder(passwordEncoderReal());
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {

        //add your custom encoding filter as the first filter in the chain
        http.addFilterBefore(new EncodingFilter(), ChannelProcessingFilter.class);

        http.formLogin()
                // указываем страницу с формой логина
                // не html, а путь контроллера, на него он error будет отправлять
                .loginPage("/logincustom")
                //указываем логику обработки при логине
//                .successHandler(new SuccessUserHandler()) // !!! ПРОВЕРИТЬ
                .successHandler(successUserHandler)
                // указываем action с формы логина
                .loginProcessingUrl("/logincustom")
                // Указываем параметры логина и пароля с формы логина
                .usernameParameter("j_email")
                .passwordParameter("j_password")
                // даем доступ к форме логина всем
//                .failureHandler(authenticationFailureHandler())
                .permitAll();

        http.logout()
                // разрешаем делать логаут всем
                .permitAll()
                // указываем URL логаута
                .logoutRequestMatcher(new AntPathRequestMatcher("/logout"))
                // указываем URL при удачном логауте
                .logoutSuccessUrl("/logincustom?logout")
                //выклчаем кроссдоменную секьюрность (на этапе обучения неважна)
                .and().csrf().disable();

        http
                // делаем страницу регистрации недоступной для авторизированных пользователей
                .authorizeRequests()
                //страницы аутентификаци доступна всем
                .antMatchers("/logincustom", "/registration").anonymous()
                .antMatchers("/", "/css/**", "/image/**", "/js/**").permitAll()
                .antMatchers("/user/acc/**", "/user-b").access("hasAnyRole('ROLE_USER', 'ROLE_ADMIN')")
                .antMatchers("/admin-b", "/registration-b").access("hasAnyRole('ROLE_ADMIN')")
                // защищенные URL
                .anyRequest().authenticated();
    }

    @Bean
    public static BCryptPasswordEncoder passwordEncoderReal() {
        return new BCryptPasswordEncoder();
    }

//    @Bean(name = BeanIds.AUTHENTICATION_MANAGER)
    @Bean
    @Override
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }

//    @Bean
//    public AuthenticationFailureHandler authenticationFailureHandler() {
//        return new CustomAuthenticationFailureHandler();
//    }
}

