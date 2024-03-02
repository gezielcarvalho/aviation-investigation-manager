package info.gezielcarvalho.aerojudic.config;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.lang.NonNull;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtService jwtService;
    private final UserDetailsService userDetailsService;

    @Override
    protected void doFilterInternal(
            @NonNull HttpServletRequest request,
            @NonNull HttpServletResponse response,
            @NonNull FilterChain filterChain) throws ServletException, IOException {
        final String authorizationHeader = request.getHeader("Authorization");
        final String tokenPrefix = "Bearer ";
        // if authorization header is not null and does not start with token prefix
        if (authorizationHeader != null) {
            // if authorization header is not null and does not start with token prefix
            if (!authorizationHeader.startsWith(tokenPrefix)) {
                filterChain.doFilter(request, response);
                return;
            }
            final String token = authorizationHeader.replace(tokenPrefix, "");
            // extract user email from token
            final String userEmail = jwtService.extractUsername(token);
            // if user email is not null and the user is not authenticated
            if (userEmail != null && SecurityContextHolder.getContext().getAuthentication() == null) {
                // get user details from user email
                final UserDetails userDetails = userDetailsService.loadUserByUsername(userEmail);
                // if token is valid
                if (jwtService.isTokenValid(token, userDetails)) {
                    // create authentication object
                    final UsernamePasswordAuthenticationToken authToken =
                            new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
                    // set authentication object in security context
                    SecurityContextHolder.getContext().setAuthentication(authToken);
                }
            }
        }
        filterChain.doFilter(request, response);
    }
}
