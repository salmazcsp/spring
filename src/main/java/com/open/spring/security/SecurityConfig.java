package com.open.spring.security;

import java.util.LinkedHashMap;
import java.util.Map;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.util.matcher.OrRequestMatcher;
import org.springframework.security.web.util.matcher.RegexRequestMatcher;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import jakarta.servlet.http.HttpServletResponse;

@Configuration
@EnableMethodSecurity
public class SecurityConfig {

    @Autowired
    private JwtAuthenticationEntryPoint jwtAuthenticationEntryPoint;

    @Autowired
    private JwtRequestFilter jwtRequestFilter;

    @Autowired
    private RateLimitFilter rateLimitFilter;

    @Bean
    @Order(1)
    public SecurityFilterChain apiSecurityFilterChain(HttpSecurity http) throws Exception {
        http
            .securityMatcher(new OrRequestMatcher(
                new RegexRequestMatcher("^/api(?:/.*)?$", null),
                new RegexRequestMatcher("^/authenticate$", null)
            ))
            .cors(Customizer.withDefaults())
            .csrf(csrf -> csrf.disable())
            .sessionManagement(session ->
                session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
            .requestCache(cache -> cache.disable())
            .authorizeHttpRequests(auth -> auth

                // CORS preflight
                .requestMatchers(HttpMethod.OPTIONS, "/**").permitAll()

                // Authentication
                .requestMatchers("/authenticate").permitAll()
                .requestMatchers(HttpMethod.POST, "/api/logout").permitAll()

                // Person endpoints
                .requestMatchers(HttpMethod.DELETE, "/api/person/**").hasAuthority("ROLE_ADMIN")
                .requestMatchers(HttpMethod.PUT, "/api/person/**").hasAuthority("ROLE_ADMIN")
                .requestMatchers(HttpMethod.POST, "/api/person/create").permitAll()
                .requestMatchers(HttpMethod.GET, "/api/person/uid/**").permitAll()

                // Public or role-specific endpoints
                .requestMatchers("/api/scraper/**")
                    .hasAnyAuthority("ROLE_USER", "ROLE_ADMIN", "ROLE_TEACHER", "ROLE_STUDENT")
                .requestMatchers("/api/gist-connection", "/api/gist-connection/").authenticated()
                .requestMatchers("/api/ai-connections", "/api/ai-connections/**").authenticated()
                .requestMatchers(HttpMethod.POST, "/api/grades/create-gist").authenticated()
                .requestMatchers(HttpMethod.GET, "/api/grades/read-gist/**").permitAll()
                .requestMatchers("/api/make/**").permitAll()

                // Face endpoints
                .requestMatchers(HttpMethod.POST,
                    "/api/face/register/public", "/api/face/register/public/").permitAll()
                .requestMatchers(HttpMethod.GET, "/api/face/faces")
                    .hasAnyAuthority("ROLE_TEACHER", "ROLE_ADMIN")
                .requestMatchers(HttpMethod.POST, "/api/face/register")
                    .hasAnyAuthority("ROLE_USER", "ROLE_STUDENT", "ROLE_TEACHER", "ROLE_ADMIN")
                .requestMatchers("/api/face/**")
                    .hasAnyAuthority("ROLE_TEACHER", "ROLE_ADMIN")

                // Games and content
                .requestMatchers(HttpMethod.DELETE, "/api/pausemenu/**")
                    .hasAuthority("ROLE_ADMIN")
                .requestMatchers("/api/pausemenu/**").permitAll()
                .requestMatchers("/api/leaderboard/**").permitAll()
                .requestMatchers("/api/gamer/**")
                    .hasAnyAuthority("ROLE_USER", "ROLE_ADMIN", "ROLE_TEACHER", "ROLE_STUDENT")
                .requestMatchers("/api/jokes/**")
                    .hasAnyAuthority("ROLE_USER", "ROLE_ADMIN", "ROLE_TEACHER", "ROLE_STUDENT")
                .requestMatchers("/api/exports/**").hasAuthority("ROLE_ADMIN")
                .requestMatchers("/api/imports/**").hasAuthority("ROLE_ADMIN")
                .requestMatchers("/api/content/**")
                    .hasAnyAuthority("ROLE_STUDENT", "ROLE_TEACHER", "ROLE_ADMIN")
                .requestMatchers("/api/collections/**")
                    .hasAnyAuthority("ROLE_STUDENT", "ROLE_TEACHER", "ROLE_ADMIN")
                .requestMatchers("/api/events/**")
                    .hasAnyAuthority("ROLE_STUDENT", "ROLE_TEACHER", "ROLE_ADMIN")

                // Synergy
                .requestMatchers(HttpMethod.POST, "/api/synergy/grades/requests")
                    .hasAnyAuthority("ROLE_STUDENT", "ROLE_TEACHER", "ROLE_ADMIN")
                .requestMatchers(HttpMethod.DELETE, "/api/synergy/saigai/")
                    .hasAnyAuthority("ROLE_STUDENT", "ROLE_TEACHER", "ROLE_ADMIN")
                .requestMatchers(HttpMethod.POST, "/api/synergy/**")
                    .hasAnyAuthority("ROLE_TEACHER", "ROLE_ADMIN")

                // AI endpoints
                .requestMatchers(HttpMethod.POST, "/api/upai")
                    .hasAnyAuthority("ROLE_USER", "ROLE_ADMIN", "ROLE_TEACHER", "ROLE_STUDENT")
                .requestMatchers(HttpMethod.GET, "/api/upai/**")
                    .hasAnyAuthority("ROLE_USER", "ROLE_ADMIN", "ROLE_TEACHER", "ROLE_STUDENT")
                .requestMatchers("/api/gemini-frq/**")
                    .hasAnyAuthority("ROLE_USER", "ROLE_ADMIN", "ROLE_TEACHER", "ROLE_STUDENT")

                // Certificates and quests
                .requestMatchers(HttpMethod.POST, "/api/quests/**")
                    .hasAnyAuthority("ROLE_TEACHER", "ROLE_ADMIN")
                .requestMatchers(HttpMethod.PUT, "/api/quests/**")
                    .hasAnyAuthority("ROLE_TEACHER", "ROLE_ADMIN")
                .requestMatchers(HttpMethod.DELETE, "/api/quests/**")
                    .hasAnyAuthority("ROLE_TEACHER", "ROLE_ADMIN")
                .requestMatchers(HttpMethod.POST, "/api/certificates/**")
                    .hasAnyAuthority("ROLE_TEACHER", "ROLE_ADMIN")
                .requestMatchers(HttpMethod.DELETE, "/api/certificates/**")
                    .hasAnyAuthority("ROLE_TEACHER", "ROLE_ADMIN")
                .requestMatchers(HttpMethod.PUT, "/api/certificates/**")
                    .hasAnyAuthority("ROLE_TEACHER", "ROLE_ADMIN")
                .requestMatchers(HttpMethod.POST, "/api/user-certificates/**")
                    .hasAnyAuthority("ROLE_TEACHER", "ROLE_ADMIN")
                .requestMatchers(HttpMethod.DELETE, "/api/user-certificates/**")
                    .hasAnyAuthority("ROLE_TEACHER", "ROLE_ADMIN")

                // Legacy authenticated APIs
                .requestMatchers("/api/analytics/**")
                    .hasAnyAuthority("ROLE_USER", "ROLE_ADMIN", "ROLE_TEACHER", "ROLE_STUDENT")
                .requestMatchers("/api/grades**")
                    .hasAnyAuthority("ROLE_USER", "ROLE_ADMIN", "ROLE_TEACHER", "ROLE_STUDENT")
                .requestMatchers("/api/plant/**")
                    .hasAnyAuthority("ROLE_USER", "ROLE_ADMIN", "ROLE_TEACHER", "ROLE_STUDENT")
                .requestMatchers("/api/groups/**")
                    .hasAnyAuthority("ROLE_USER", "ROLE_ADMIN", "ROLE_TEACHER", "ROLE_STUDENT")
                .requestMatchers("/api/grade-prediction/**")
                    .hasAnyAuthority("ROLE_USER", "ROLE_ADMIN", "ROLE_TEACHER", "ROLE_STUDENT")
                .requestMatchers("/api/admin-evaluation/**")
                    .hasAnyAuthority("ROLE_USER", "ROLE_ADMIN", "ROLE_TEACHER", "ROLE_STUDENT")
                .requestMatchers("/api/grades/**")
                    .hasAnyAuthority("ROLE_USER", "ROLE_ADMIN", "ROLE_TEACHER", "ROLE_STUDENT")
                .requestMatchers("/api/progress/**")
                    .hasAnyAuthority("ROLE_USER", "ROLE_ADMIN", "ROLE_TEACHER", "ROLE_STUDENT")
                .requestMatchers("/api/calendar/**")
                    .hasAnyAuthority("ROLE_USER", "ROLE_ADMIN", "ROLE_TEACHER", "ROLE_STUDENT")
                .requestMatchers("/api/chat/**")
                    .hasAnyAuthority("ROLE_USER", "ROLE_ADMIN", "ROLE_TEACHER", "ROLE_STUDENT")
                .requestMatchers("/api/email/**")
                    .hasAnyAuthority("ROLE_USER", "ROLE_ADMIN", "ROLE_TEACHER", "ROLE_STUDENT")
                .requestMatchers("/api/files/**")
                    .hasAnyAuthority("ROLE_USER", "ROLE_ADMIN", "ROLE_TEACHER", "ROLE_STUDENT")
                .requestMatchers(HttpMethod.GET, "/api/sprint-dates/**")
                    .hasAnyAuthority("ROLE_USER", "ROLE_ADMIN", "ROLE_TEACHER", "ROLE_STUDENT")

                // Challenge submissions
                .requestMatchers(HttpMethod.POST, "/api/challenge-submission/**")
                    .hasAnyAuthority("ROLE_USER", "ROLE_ADMIN", "ROLE_TEACHER", "ROLE_STUDENT")

                // Assignment sync and submissions
                .requestMatchers(HttpMethod.POST, "/api/assignments/auto-create")
                    .hasAnyAuthority(
                        "ROLE_USER", "ROLE_ADMIN", "ROLE_TEACHER",
                        "ROLE_STUDENT", "ROLE_ASSIGNMENT_SYNC")
                .requestMatchers(HttpMethod.POST, "/api/submissions/**").authenticated()
                .requestMatchers(HttpMethod.POST, "/api/assignment-submissions/upload")
                    .permitAll()

                // CS pathway
                .requestMatchers(HttpMethod.POST,
                    "/api/cs-pathway/setup-report/pairing-code")
                    .hasAnyAuthority("ROLE_USER", "ROLE_ADMIN", "ROLE_TEACHER", "ROLE_STUDENT")
                .requestMatchers(HttpMethod.POST,
                    "/api/cs-pathway/setup-report/review/**")
                    .hasAnyAuthority("ROLE_ADMIN", "ROLE_TEACHER")
                .requestMatchers(HttpMethod.POST, "/api/cs-pathway/setup-report/*")
                    .permitAll()

                // Toolchain pairing
                .requestMatchers(HttpMethod.POST, "/api/toolchain/pair").permitAll()
                .requestMatchers(HttpMethod.GET, "/api/toolchain/sessions/*/next")
                    .permitAll()
                .requestMatchers(HttpMethod.POST, "/api/toolchain/sessions/*/results")
                    .permitAll()

                // OCS analytics
                .requestMatchers("/api/ocs-analytics/**")
                    .hasAnyAuthority("ROLE_USER", "ROLE_ADMIN", "ROLE_TEACHER", "ROLE_STUDENT")

                // UI builder public pages
                .requestMatchers(HttpMethod.GET,
                    "/api/ui-builder/published", "/api/ui-builder/published/*")
                    .permitAll()

                // Default: all remaining API endpoints require authentication
                .requestMatchers("/api/**")
                    .hasAnyAuthority("ROLE_USER", "ROLE_ADMIN", "ROLE_TEACHER", "ROLE_STUDENT")
            )
            .exceptionHandling(exceptions -> exceptions
                .authenticationEntryPoint(jwtAuthenticationEntryPoint)
                .accessDeniedHandler((request, response, accessDeniedException) -> {
                    response.setStatus(HttpServletResponse.SC_FORBIDDEN);
                    response.setContentType("application/json");
                    response.setCharacterEncoding("UTF-8");
                    response.getWriter().write(
                        "{\"error\":\"Forbidden\",\"message\":\"You do not have permission to access this resource.\"}"
                    );
                    response.getWriter().flush();
                }))
            .addFilterBefore(jwtRequestFilter, UsernamePasswordAuthenticationFilter.class)
            .addFilterAfter(rateLimitFilter, JwtRequestFilter.class);

        return http.build();
    }

    @Bean(name = "apiEndpointRolePolicy")
    public Map<String, String> apiEndpointRolePolicy() {
        Map<String, String> policy = new LinkedHashMap<>();

        policy.put("/authenticate", "permitAll");
        policy.put("POST /authenticate", "permitAll");
        policy.put("/api/person/create", "permitAll");
        policy.put("/api/person/create/", "permitAll");
        policy.put("POST /api/person/create", "permitAll");
        policy.put("DELETE /api/person/**", "ROLE_ADMIN");
        policy.put("PUT /api/person/**", "ROLE_ADMIN");
        policy.put("GET /api/person/uid/**", "permitAll");

        policy.put("POST /api/face/register/public", "permitAll");
        policy.put("GET /api/face/faces", "ROLE_TEACHER|ROLE_ADMIN");
        policy.put("POST /api/face/register",
            "ROLE_USER|ROLE_STUDENT|ROLE_TEACHER|ROLE_ADMIN");
        policy.put("/api/face/**", "ROLE_TEACHER|ROLE_ADMIN");

        policy.put("POST /api/assignment-submissions/upload", "permitAll");
        policy.put("POST /api/assignments/auto-create",
            "ROLE_USER|ROLE_ADMIN|ROLE_TEACHER|ROLE_STUDENT|ROLE_ASSIGNMENT_SYNC");

        policy.put("/api/gist-connection", "authenticated");
        policy.put("/api/ai-connections", "authenticated");
        policy.put("/api/ai-connections/**", "authenticated");
        policy.put("POST /api/submissions/**", "authenticated");
        policy.put("POST /api/grades/create-gist", "authenticated");

        policy.put("POST /api/cs-pathway/setup-report/pairing-code",
            "ROLE_USER|ROLE_ADMIN|ROLE_TEACHER|ROLE_STUDENT");
        policy.put("POST /api/cs-pathway/setup-report/review/**",
            "ROLE_ADMIN|ROLE_TEACHER");
        policy.put("POST /api/cs-pathway/setup-report/*", "permitAll");

        policy.put("POST /api/toolchain/pair", "permitAll");
        policy.put("GET /api/toolchain/sessions/*/next", "permitAll");
        policy.put("POST /api/toolchain/sessions/*/results", "permitAll");

        policy.put("DELETE /api/pausemenu/**", "ROLE_ADMIN");
        policy.put("/api/pausemenu/**", "permitAll");
        policy.put("/api/leaderboard/**", "permitAll");
        policy.put("/api/exports/**", "ROLE_ADMIN");
        policy.put("/api/imports/**", "ROLE_ADMIN");

        policy.put("GET /api/ui-builder/published", "permitAll");
        policy.put("GET /api/ui-builder/published/*", "permitAll");

        policy.put("/api/**",
            "ROLE_USER|ROLE_ADMIN|ROLE_TEACHER|ROLE_STUDENT");

        return Map.copyOf(policy);
    }

    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();

        configuration.setAllowCredentials(true);

        // Oak frontend
        configuration.addAllowedOriginPattern("https://oak404.github.io");

        // Open Coding Society origins
        configuration.addAllowedOriginPattern("https://*.opencodingsociety.com");
        configuration.addAllowedOriginPattern("https://open-coding-society.github.io");
        configuration.addAllowedOriginPattern("https://opencodingsociety.com");
        configuration.addAllowedOriginPattern("http://opencodingsociety.com");
        configuration.addAllowedOriginPattern("https://pages.opencodingsociety.com");
        configuration.addAllowedOriginPattern("https://spring.opencodingsociety.com");

        // Local development
        configuration.addAllowedOriginPattern("http://127.0.0.1:4500");
        configuration.addAllowedOriginPattern("http://127.0.0.1:4599");
        configuration.addAllowedOriginPattern("http://127.0.0.1:4600");
        configuration.addAllowedOriginPattern("http://127.0.0.1:8585");
        configuration.addAllowedOriginPattern("http://127.0.0.1:4000");
        configuration.addAllowedOriginPattern("http://localhost:4000");
        configuration.addAllowedOriginPattern("http://localhost:4500");
        configuration.addAllowedOriginPattern("http://localhost:4599");
        configuration.addAllowedOriginPattern("http://localhost:4600");
        configuration.addAllowedOriginPattern("http://localhost:8585");

        configuration.addAllowedHeader("*");
        configuration.addAllowedMethod("*");

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        return source;
    }
}